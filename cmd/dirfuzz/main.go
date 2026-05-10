package main

import (
	"fmt"
	"os"

	"dirfuzz/pkg/engine"
)

func main() {
	cfg := parseFlags()

	if cfg.ActivePoC != "" {
		fmt.Fprintf(os.Stderr, "[*] Running Active PoC plugin: %s\n", cfg.ActivePoC)
		
		proxy := cfg.ProxyOut
		if proxy == "" && cfg.ProxyFile != "" {
			fmt.Fprintf(os.Stderr, "[!] Warning: --proxy (file) is ignored by Active PoC. Use --proxy-out for a single proxy.\n")
		}

		err := engine.RunActiveTemplate(cfg.ActivePoC, cfg.Timeout, proxy, cfg.Insecure, cfg.Target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: active poc failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if !cfg.NoTUI {
		// Print a brief startup banner to stderr before the TUI takes over.
		// This is immediately replaced by the alt-screen, so it only flashes
		// briefly in terminals that support alt-screen. It gives users without
		// alt-screen support (e.g. piped output) a visible indication of what
		// is running.
		fmt.Fprintf(os.Stderr,
			"🦇 DirFuzz v%s  →  %s\n",
			cliVersion, cfg.Target,
		)
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

