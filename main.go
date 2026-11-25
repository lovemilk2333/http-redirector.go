package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/alexflint/go-arg"
)

var args struct {
	ConfigPath string `arg:"env:CONFIG_PATH,-c,--config-path" default:"config.yaml" help:"config file path"`
}

func main() {
	arg.MustParse(&args)

	cl := &ConfigLoader{
		filename: args.ConfigPath,
	}

	if err := cl.Load(); err != nil {
		panic(err)
	}
	_ = cl.Save()

	c := cl.Config()
	if err := initLogger(c.LogLevel, c.LogSource, c.LogJSON); err != nil {
		panic(err)
	}
	if maybeInstallAndroidDNSResolver() {
		slog.Debug("Android DNS resolver enabled", "socket", androidDNSProxySocket)
	}

	slog.Info("inited")

	if c.ProxyPort == 0 && c.HTTPPort == 0 {
		slog.Error("no service config found")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	var servers []*http.Server

	if c.ProxyPort != 0 {
		listen := "127.0.0.1:" + strconv.FormatUint(uint64(c.ProxyPort), 10)
		proxyServer := &http.Server{
			Addr:    listen,
			Handler: http.HandlerFunc(NewHandler(cl, false)),
		}
		servers = append(servers, proxyServer)

		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Warn("proxy server started at http://" + listen)
			if err := proxyServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("proxy server error", "err", err)
				stop()
			}
		}()
	}

	if c.HTTPPort != 0 {
		listen := "127.0.0.1:" + strconv.FormatUint(uint64(c.HTTPPort), 10)
		httpServer := &http.Server{
			Addr:    listen,
			Handler: http.HandlerFunc(NewHandler(cl, true)),
		}
		servers = append(servers, httpServer)

		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Warn("HTTP server started at http://" + listen)
			if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("HTTP server error", "err", err)
				stop()
			}
		}()
	}

	// TODO Admin API

	<-ctx.Done()

	slog.Warn("shutting down servers...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown error", "addr", srv.Addr, "err", err)
		}
	}

	wg.Wait()
	slog.Warn("all servers stopped")
}
