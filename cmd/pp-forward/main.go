package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/LordDeveloper/agent/internal/ppforward"
)

const version = "0.1.0"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "version", "-version", "--version":
		fmt.Println(version)
		os.Exit(0)
	case "help", "-h", "--help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `pp-forward %s — TCP PROXY protocol v1 forwarder (IPv4)

Usage:
  pp-forward serve --config /path/to/config.json [--lock /path/to/lock]
  pp-forward version

Config JSON:
  {"rules":[{"listen":"0.0.0.0:2053","target":"127.0.0.1:2054","tag":"inbound-1"}]}
`, version)
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to JSON config")
	lockPath := fs.String("lock", "", "optional flock file path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "--config is required")
		return 2
	}

	cfg, err := ppforward.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	logger := log.New(os.Stdout, "pp-forward ", log.LstdFlags|log.Lmicroseconds)

	var lockFile *os.File
	if *lockPath != "" {
		lockFile, err = ppforward.AcquireLock(*lockPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer lockFile.Close()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	server := ppforward.NewServer(cfg, logger)
	if err := server.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
