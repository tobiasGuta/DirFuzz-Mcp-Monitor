package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"dirfuzz/pkg/engine"
)

const (
	HistoryModeOverwrite = "overwrite"
	HistoryModeAppend    = "append"
)

func normalizeHistoryMode(raw string) string {
	mode := strings.ToLower(strings.TrimSpace(raw))
	if mode == "" {
		return HistoryModeOverwrite
	}
	return mode
}

func validateHistoryMode(cfg cliConfig) error {
	switch cfg.HistoryMode {
	case HistoryModeOverwrite, HistoryModeAppend:
	default:
		return fmt.Errorf("invalid --history-mode %q: expected overwrite or append", cfg.HistoryMode)
	}

	if cfg.HistoryMode != HistoryModeAppend {
		return nil
	}
	if strings.TrimSpace(cfg.OutputFile) == "" {
		return fmt.Errorf("--history-mode=append requires -o <results.jsonl>")
	}
	if cfg.OutputFormat != engine.DefaultOutputFormat {
		return fmt.Errorf("--history-mode=append only supports -of %s", engine.DefaultOutputFormat)
	}
	return nil
}

func outputFileOpenFlags(historyMode string) int {
	if historyMode == HistoryModeAppend {
		return os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	return os.O_CREATE | os.O_WRONLY | os.O_TRUNC
}

func loadPersistedResults(path string) ([]engine.Result, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	results := make([]engine.Result, 0, 128)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var res engine.Result
		if err := res.UnmarshalJSON([]byte(line)); err != nil {
			continue
		}
		results = append(results, res)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
