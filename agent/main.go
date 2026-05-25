// Package main — detection-validator lightweight telemetry agent.
// Cross-platform forwarder that ships host telemetry (logs, events, metrics)
// to the detection-validator core service or directly to a SIEM backend.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const version = "0.1.0"

func main() {
	var (
		endpoint   = flag.String("endpoint", "http://localhost:8080", "Detection validator core endpoint URL")
		agentID    = flag.String("id", "", "Agent ID (auto-generated if empty)")
		logLevel   = flag.String("log-level", "info", "Log level: debug|info|warn|error")
		apiKey     = flag.String("api-key", "", "API key for authentication")
		showVersion = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("dv-agent v%s\n", version)
		os.Exit(0)
	}

	// Configure structured logging
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	if *agentID == "" {
		hostname, _ := os.Hostname()
		*agentID = hostname
	}

	slog.Info("dv-agent starting",
		"version", version,
		"agent_id", *agentID,
		"endpoint", *endpoint,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	agent := &Agent{
		ID:       *agentID,
		Endpoint: *endpoint,
		APIKey:   *apiKey,
		Logger:   logger,
	}

	if err := agent.Run(ctx); err != nil {
		slog.Error("agent exited with error", "error", err)
		os.Exit(1)
	}
}

// Agent manages a persistent connection to the detection-validator core.
type Agent struct {
	ID       string
	Endpoint string
	APIKey   string
	Logger   *slog.Logger
}

// Run starts the agent event loop and blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.Logger.Info("agent running — TODO: implement event collection and forwarding",
		"id", a.ID, "endpoint", a.Endpoint)

	// TODO: implement telemetry collection (auditd, syslog, Windows Event Log)
	// TODO: implement batched HTTP forwarding to core endpoint
	// TODO: implement reconnect / back-off logic

	<-ctx.Done()
	a.Logger.Info("agent shutting down gracefully")
	return nil
}
