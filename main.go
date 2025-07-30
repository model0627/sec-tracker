package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sec-tracker/internal/agent"
	"github.com/sec-tracker/internal/config"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	// Command line flags
	var (
		configFile = flag.String("config", "config.json", "Configuration file path")
		localMode  = flag.Bool("local", false, "Run in local mode (output to terminal instead of server)")
		oneShot    = flag.Bool("oneshot", false, "Run once and exit (only in local mode)")
		jsonOutput = flag.Bool("json", false, "Output in JSON format (local mode only)")
		showVersion = flag.Bool("version", false, "Show version information")
		help       = flag.Bool("help", false, "Show help information")
	)
	flag.Parse()

	// Show version
	if *showVersion {
		fmt.Printf("Security Tracker Agent\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Go Version: %s\n", os.Getenv("GO_VERSION"))
		return
	}

	// Show help
	if *help {
		showHelp()
		return
	}

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Override config for local mode
	if *localMode {
		cfg.LocalMode = true
		cfg.LocalOutput.JSONFormat = *jsonOutput
		cfg.LocalOutput.OneShot = *oneShot
	}

	// Create agent
	secAgent, err := agent.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		if *localMode {
			fmt.Println("\nReceived shutdown signal, stopping agent...")
		} else {
			log.Println("Received shutdown signal, stopping agent...")
		}
		cancel()
	}()

	// Start the agent
	if *localMode {
		fmt.Println("Starting Security Tracker Agent in LOCAL mode...")
		fmt.Printf("Agent ID: %s\n", cfg.Agent.ID)
		fmt.Printf("Output Format: %s\n", getOutputFormat(*jsonOutput))
		fmt.Printf("Mode: %s\n\n", getRunMode(*oneShot))
		
		if *oneShot {
			fmt.Println("=== ONE-SHOT SYSTEM SCAN ===")
		} else {
			fmt.Println("=== CONTINUOUS MONITORING ===")
			fmt.Println("Press Ctrl+C to stop...\n")
		}
	} else {
		log.Println("Starting Security Tracker Agent...")
	}

	if err := secAgent.Start(ctx); err != nil {
		log.Fatalf("Agent failed: %v", err)
	}

	if *localMode {
		fmt.Println("\nAgent stopped")
	} else {
		log.Println("Agent stopped gracefully")
	}
}

func showHelp() {
	fmt.Printf("Security Tracker Agent v%s\n\n", Version)
	fmt.Println("USAGE:")
	fmt.Println("  sec-tracker [options]")
	fmt.Println("")
	fmt.Println("OPTIONS:")
	fmt.Println("  -config string")
	fmt.Println("        Configuration file path (default \"config.json\")")
	fmt.Println("  -local")
	fmt.Println("        Run in local mode (output to terminal instead of server)")
	fmt.Println("  -oneshot")
	fmt.Println("        Run once and exit (only works with -local)")
	fmt.Println("  -json")
	fmt.Println("        Output in JSON format (only works with -local)")
	fmt.Println("  -version")
	fmt.Println("        Show version information")
	fmt.Println("  -help")
	fmt.Println("        Show this help message")
	fmt.Println("")
	fmt.Println("EXAMPLES:")
	fmt.Println("  # Run as daemon (send data to server)")
	fmt.Println("  sec-tracker")
	fmt.Println("")
	fmt.Println("  # Monitor in terminal (human-readable)")
	fmt.Println("  sec-tracker -local")
	fmt.Println("")
	fmt.Println("  # One-shot system scan (JSON output)")
	fmt.Println("  sec-tracker -local -oneshot -json")
	fmt.Println("")
	fmt.Println("  # Monitor with custom config")
	fmt.Println("  sec-tracker -local -config /path/to/config.json")
}

func getOutputFormat(json bool) string {
	if json {
		return "JSON"
	}
	return "Human-readable"
}

func getRunMode(oneshot bool) string {
	if oneshot {
		return "One-shot"
	}
	return "Continuous"
} 