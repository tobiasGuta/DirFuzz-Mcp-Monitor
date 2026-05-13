//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	b, err := os.ReadFile("pkg/tui/tui.go")
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(b), "\n")
	count := 0
	lastFunc := ""
	for i, line := range lines {
		// rough strip of single-line comments
		if idx := strings.Index(line, "//"); idx != -1 {
			line = line[:idx]
		}

		if strings.HasPrefix(line, "func ") {
			lastFunc = line
		}

		for _, c := range line {
			if c == '{' {
				count++
			}
			if c == '}' {
				count--
			}
		}

		if count == 0 && strings.HasPrefix(strings.TrimSpace(line), "}") {
			fmt.Printf("Line %d: block closed. Last func: %s\n", i+1, lastFunc)
		}
	}
	fmt.Printf("Final count: %d\n", count)
}
