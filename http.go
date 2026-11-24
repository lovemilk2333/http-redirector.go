package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

func NewHandler(cl *ConfigLoader, isHTTP bool) http.HandlerFunc {
	return newHandler(cl, isHTTP, http.DefaultTransport)
}

func newHandler(cl *ConfigLoader, isHTTP bool, transport http.RoundTripper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("request received", slog.String("method", r.Method), slog.String("host", r.Host), slog.String("from", r.RemoteAddr), slog.Bool("http_listener", isHTTP))
		if !isHTTP && r.Method == http.MethodConnect {
			forwardConnect(w, r, cl.Config())
			return
		}

		host, err := parseRequestHost(r)
		if err != nil {
			slog.Debug("request ended early", slog.String("reason", "invalid request host"), slog.String("host", r.Host), slog.String("from", r.RemoteAddr), slog.Any("error", err))
			http.Error(w, "invalid request host", http.StatusBadRequest)
			return
		}

		config := cl.Config()
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		upgradeToHTTPS := shouldUpgradeToHTTPS(config, host)
		if err := forwardHTTPWithTransport(w, r, upgradeToHTTPS, transport); err != nil {
			slog.Debug("request forwarding failed", slog.String("host", host), slog.String("from", r.RemoteAddr), slog.Any("error", err))
			http.Error(w, "upstream request failed", http.StatusBadGateway)
		}
	}
}

func shouldUpgradeToHTTPS(config *Config, host string) bool {
	addr, err := netip.ParseAddr(host)
	if err == nil {
		return config.MatchRedirectAddr(addr) && !config.MatchBypassAddr(addr)
	}
	return config.MatchRedirectDomain(host) && !config.MatchBypassDomain(host)
}

func forwardHTTPWithTransport(w http.ResponseWriter, r *http.Request, upgradeToHTTPS bool, transport http.RoundTripper) error {
	target := *r.URL
	if !target.IsAbs() {
		target.Scheme = "http"
		target.Host = r.Host
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return fmt.Errorf("unsupported upstream scheme %q", target.Scheme)
	}
	if target.Host == "" {
		return fmt.Errorf("upstream host is empty")
	}
	if upgradeToHTTPS {
		host, port, err := net.SplitHostPort(target.Host)
		if err != nil {
			host = strings.TrimSuffix(strings.TrimPrefix(target.Host, "["), "]")
			if target.Scheme == "http" {
				port = "80"
			}
		}
		if port == "80" {
			target.Host = net.JoinHostPort(host, "443")
		}
		target.Scheme = "https"
	}
	slog.Debug("forwarding request", slog.String("method", r.Method), slog.String("host", target.Host), slog.String("scheme", target.Scheme), slog.String("from", r.RemoteAddr))

	outgoing := r.Clone(r.Context())
	outgoing.URL = &target
	outgoing.RequestURI = ""
	outgoing.Host = target.Host
	removeHopByHopHeaders(outgoing.Header)
	outgoing.Header.Del("Proxy-Authorization")
	outgoing.Header.Del("Proxy-Authenticate")
	response, err := transport.RoundTrip(outgoing)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	slog.Debug("upstream response received", slog.String("method", r.Method), slog.String("host", target.Host), slog.String("scheme", target.Scheme), slog.Int("status", response.StatusCode), slog.String("from", r.RemoteAddr))
	removeHopByHopHeaders(response.Header)
	copyResponseHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, response.Body); err != nil {
		slog.Debug("upstream response copy failed", slog.String("host", target.Host), slog.Any("error", err))
	}
	return nil
}

func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}

func copyResponseHeaders(destination, source http.Header) {
	for name, values := range source {
		for _, value := range values {
			destination.Add(name, value)
		}
	}
}

func connectUpstreamTarget(host string, config *Config) (address, serverName string, tlsBridge bool) {
	requestHost, port, err := net.SplitHostPort(host)
	if err != nil {
		requestHost = strings.Trim(host, "[]")
		port = "443"
	}
	if port == "" {
		port = "443"
	}
	requestHost = strings.ToLower(strings.TrimSuffix(requestHost, "."))
	tlsBridge = port == "80" && shouldUpgradeToHTTPS(config, requestHost)
	if tlsBridge {
		port = "443"
	}
	return net.JoinHostPort(requestHost, port), requestHost, tlsBridge
}

func connectUpstreamAddress(host string, config *Config) string {
	address, _, _ := connectUpstreamTarget(host, config)
	return address
}

func forwardConnect(w http.ResponseWriter, r *http.Request, config *Config) {
	address, serverName, tlsBridge := connectUpstreamTarget(r.Host, config)
	upstream, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", address)
	if err != nil {
		slog.Debug("CONNECT forwarding failed", slog.String("reason", "upstream dial failed"), slog.String("host", r.Host), slog.Any("error", err))
		http.Error(w, "upstream connection failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	if tlsBridge {
		tlsUpstream := tls.Client(upstream, &tls.Config{ServerName: serverName})
		if err := tlsUpstream.HandshakeContext(r.Context()); err != nil {
			slog.Debug("CONNECT TLS bridge failed", slog.String("reason", "upstream TLS handshake failed"), slog.String("host", r.Host), slog.String("upstream", address), slog.Any("error", err))
			http.Error(w, "upstream TLS connection failed", http.StatusBadGateway)
			return
		}
		upstream = tlsUpstream
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		slog.Debug("CONNECT forwarding failed", slog.String("reason", "response writer does not support hijacking"), slog.String("host", r.Host))
		http.Error(w, "CONNECT unsupported", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		slog.Debug("CONNECT forwarding failed", slog.String("reason", "client connection hijack failed"), slog.String("host", r.Host), slog.Any("error", err))
		return
	}
	defer client.Close()
	if _, err := fmt.Fprint(buffered, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	logMessage := "CONNECT tunnel established"
	if tlsBridge {
		logMessage = "CONNECT TLS bridge established"
	}
	slog.Debug(logMessage, slog.String("host", r.Host), slog.String("upstream", address), slog.String("from", r.RemoteAddr))
	tunnel(r.Context(), client, buffered.Reader, upstream)
}

func tunnel(ctx context.Context, client net.Conn, clientReader *bufio.Reader, upstream net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	copyStream := func(destination, source net.Conn, reader io.Reader) {
		defer wait.Done()
		_, _ = io.Copy(destination, reader)
		if closeWriter, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
	}
	go copyStream(upstream, client, io.MultiReader(clientReader, client))
	go copyStream(client, upstream, upstream)
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer stopCancellation()
	wait.Wait()
}

func parseRequestHost(r *http.Request) (string, error) {
	host := r.Host
	// if host == "" {
	// 	host = r.URL.Host
	// }
	if host == "" {
		return "", net.InvalidAddrError("empty host")
	}

	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(splitHost, "[]"), nil
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), nil
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", err
		}
	}
	return host, nil
}
