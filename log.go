package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func initLogger(level string, source bool, json bool) error {
	var logLevel slog.Level

	switch strings.ToLower(level) {
	case "false", "silent":
		return nil
	case "debug":
		logLevel = slog.LevelDebug
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		return fmt.Errorf("invalid log level: %v", level)
	}

	options := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: source,
	}

	var handler slog.Handler
	if json {
		handler = slog.NewJSONHandler(os.Stderr, options)
	} else {
		handler = slog.NewTextHandler(os.Stderr, options)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return nil
}
