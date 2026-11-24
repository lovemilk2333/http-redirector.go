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
	redirectList := []string{"+.example.com"}
	var bypassList []string
	config := &Config{RedirectList: &redirectList, BypassList: &bypassList}
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

func TestConnectUpstreamAddressUpgradesPort80ForRedirectedHost(t *testing.T) {
	redirectList := []string{"+.example.com"}
	bypassList := []string{"safe.example.com"}
	config := &Config{RedirectList: &redirectList, BypassList: &bypassList}
	if err := config.ParseRules(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "redirected host", host: "qh.example.com:80", want: "qh.example.com:443"},
		{name: "bypassed host", host: "safe.example.com:80", want: "safe.example.com:80"},
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

	if _, _, tlsBridge := connectUpstreamTarget("qh.example.com:80", config); !tlsBridge {
		t.Error("matching CONNECT request on port 80 should use a TLS bridge")
	}
	if _, _, tlsBridge := connectUpstreamTarget("safe.example.com:80", config); tlsBridge {
		t.Error("bypassed CONNECT request should remain a raw tunnel")
	}
	if _, _, tlsBridge := connectUpstreamTarget("qh.example.com:443", config); tlsBridge {
		t.Error("CONNECT request to port 443 should remain a raw tunnel")
	}
}
