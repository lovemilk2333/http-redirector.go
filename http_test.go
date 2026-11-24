package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestProxyHandlerForwardsHTTPRequest(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://upstream.example/resource?q=1", nil)
	response := httptest.NewRecorder()
	transport := roundTripFunc(func(upstream *http.Request) (*http.Response, error) {
		if got, want := upstream.URL.String(), "http://upstream.example/resource?q=1"; got != want {
			t.Errorf("upstream URL = %q, want %q", got, want)
		}
		if upstream.Host != "upstream.example" {
			t.Errorf("upstream Host = %q, want upstream.example", upstream.Host)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"X-Upstream": []string{"reached"}},
			Body:       io.NopCloser(strings.NewReader("upstream response")),
			Request:    upstream,
		}, nil
	})

	if err := forwardHTTPWithTransport(response, request, false, transport); err != nil {
		t.Fatalf("forwardHTTPWithTransport() error = %v", err)
	}
	result := response.Result()
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusOK)
	}
	if result.Header.Get("X-Upstream") != "reached" {
		t.Fatalf("upstream header = %q, want reached", result.Header.Get("X-Upstream"))
	}
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "upstream response"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestHandlerBridgesHTTPToHTTPSWithoutRedirectResponse(t *testing.T) {
	rules := []string{"+.example.com;redirect", "+.test;bypass"}
	config := &Config{Rules: &rules}
	if err := config.ParseRules(); err != nil {
		t.Fatal(err)
	}
	loader := &ConfigLoader{}
	loader.config.Store(config)

	tests := []struct {
		name       string
		url        string
		wantScheme string
		wantHost   string
	}{
		{name: "matched host upgrades", url: "http://qh.example.com:80/path", wantScheme: "https", wantHost: "qh.example.com:443"},
		{name: "unmatched host forwards directly", url: "http://other.test:80/path", wantScheme: "http", wantHost: "other.test:80"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodHead, test.url, nil)
			response := httptest.NewRecorder()
			transport := roundTripFunc(func(upstream *http.Request) (*http.Response, error) {
				if upstream.URL.Scheme != test.wantScheme || upstream.URL.Host != test.wantHost {
					t.Errorf("upstream URL = %q, want scheme %q and host %q", upstream.URL, test.wantScheme, test.wantHost)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    upstream,
				}, nil
			})

			newHandler(loader, true, transport).ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Errorf("response status = %d, want upstream status %d", response.Code, http.StatusOK)
			}
		})
	}
}

func TestHandlerAppliesFirstMatchingRule(t *testing.T) {
	rules := []string{"+.redirect.example;deny", "+.redirect.example;redirect", "+.blocked.example;bypass", "+.blocked.example;deny", "+.bypass.example;bypass"}
	config := &Config{Rules: &rules}
	if err := config.ParseRules(); err != nil {
		t.Fatal(err)
	}
	loader := &ConfigLoader{}
	loader.config.Store(config)

	tests := []struct {
		name       string
		url        string
		wantStatus int
		wantScheme string
	}{
		{name: "first deny overrides later redirect", url: "http://www.redirect.example/", wantStatus: http.StatusForbidden},
		{name: "first bypass overrides later deny", url: "http://www.blocked.example/", wantStatus: http.StatusOK, wantScheme: "http"},
		{name: "bypass forwards directly", url: "http://www.bypass.example/", wantStatus: http.StatusOK, wantScheme: "http"},
		{name: "unmatched host is denied by default", url: "http://unlisted.test/", wantStatus: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.url, nil)
			response := httptest.NewRecorder()
			transportCalled := false
			transport := roundTripFunc(func(upstream *http.Request) (*http.Response, error) {
				transportCalled = true
				if upstream.URL.Scheme != test.wantScheme {
					t.Errorf("upstream scheme = %q, want %q", upstream.URL.Scheme, test.wantScheme)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    upstream,
				}, nil
			})

			newHandler(loader, true, transport).ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Errorf("response status = %d, want %d", response.Code, test.wantStatus)
			}
			if got := transportCalled; got != (test.wantStatus == http.StatusOK) {
				t.Errorf("transport called = %t, want %t", got, test.wantStatus == http.StatusOK)
			}
		})
	}
}

func TestConnectUpstreamAddressUpgradesPort80ForRedirectedHost(t *testing.T) {
	rules := []string{"+.example.com;redirect", "safe.example.com;bypass", "safe.other.test;bypass"}
	config := &Config{Rules: &rules}
	if err := config.ParseRules(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "redirected host", host: "qh.example.com:80", want: "qh.example.com:443"},
		{name: "redirect takes precedence over bypass", host: "safe.example.com:80", want: "safe.example.com:443"},
		{name: "bypass without redirect", host: "safe.other.test:80", want: "safe.other.test:80"},
		{name: "other port", host: "qh.example.com:8080", want: "qh.example.com:8080"},
		{name: "default TLS port", host: "qh.example.com", want: "qh.example.com:443"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := connectUpstreamAddress(test.host, config); got != test.want {
				t.Errorf("connectUpstreamAddress(%q) = %q, want %q", test.host, got, test.want)
			}
		})
	}

	if _, _, tlsBridge, destination := connectUpstreamTarget("qh.example.com:80", config); !tlsBridge || destination != RuleRedirect {
		t.Error("matching CONNECT request on port 80 should use a TLS bridge")
	}
	if _, _, tlsBridge, destination := connectUpstreamTarget("safe.example.com:80", config); !tlsBridge || destination != RuleRedirect {
		t.Error("redirect should take precedence over bypass for CONNECT requests")
	}
	if _, _, tlsBridge, destination := connectUpstreamTarget("safe.other.test:80", config); tlsBridge || destination != RuleBypass {
		t.Error("bypassed CONNECT request without a redirect match should remain a raw tunnel")
	}
	if _, _, tlsBridge, _ := connectUpstreamTarget("qh.example.com:443", config); tlsBridge {
		t.Error("CONNECT request to port 443 should remain a raw tunnel")
	}
}

func TestParseRequestHostRejectsInvalidDomains(t *testing.T) {
	for _, host := range []string{"bad_name.example", "-bad.example", "bad-.example", strings.Repeat("a", MaxDomainLabelLength+1) + ".com"} {
		t.Run(host, func(t *testing.T) {
			request := &http.Request{Host: host}
			if _, err := parseRequestHost(request); err == nil {
				t.Errorf("parseRequestHost(%q) succeeded, want invalid-domain error", host)
			}
		})
	}
}
