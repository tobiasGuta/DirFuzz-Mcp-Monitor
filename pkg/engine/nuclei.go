package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"

	"github.com/google/shlex"
)

func (e *Engine) startNuclei() error {
	e.Config.RLock()
	enabled := e.Config.Nuclei
	argsStr := e.Config.NucleiArgs
	e.Config.RUnlock()

	if !enabled {
		return nil
	}

	args, err := shlex.Split(argsStr)
	if err != nil {
		return fmt.Errorf("failed to parse nuclei args: %w", err)
	}

	cmdArgs := []string{"-silent", "-jsonl"}
	cmdArgs = append(cmdArgs, args...)

	e.nucleiCmd = exec.Command("nuclei", cmdArgs...)
	
	stdin, err := e.nucleiCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("nuclei stdin: %w", err)
	}
	e.nucleiStdin = stdin

	stdout, err := e.nucleiCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("nuclei stdout: %w", err)
	}

	if err := e.nucleiCmd.Start(); err != nil {
		return fmt.Errorf("starting nuclei: %w", err)
	}

	e.nucleiWg.Add(1)
	go e.monitorNucleiStdout(stdout)

	return nil
}

func (e *Engine) stopNuclei() {
	if e.nucleiStdin != nil {
		e.nucleiStdin.Close()
	}
	if e.nucleiCmd != nil {
		e.nucleiCmd.Wait()
	}
	e.nucleiWg.Wait()
}

func (e *Engine) SubmitToNuclei(url string) {
	e.Config.RLock()
	enabled := e.Config.Nuclei
	e.Config.RUnlock()
	if !enabled || e.nucleiStdin == nil {
		return
	}
	
	// 5.7 Deduplication
	if _, loaded := e.nucleiSeen.LoadOrStore(url, true); loaded {
		return
	}
	
	e.nucleiMu.Lock()
	defer e.nucleiMu.Unlock()
	fmt.Fprintf(e.nucleiStdin, "%s\n", url)
}

func (e *Engine) monitorNucleiStdout(stdout io.Reader) {
	defer e.nucleiWg.Done()
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Bytes()
		var nRes struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Severity    string   `json:"severity"`
				Tags        []string `json:"tags"`
			} `json:"info"`
			Type             string `json:"type"`
			Host             string `json:"host"`
			MatchedAt        string `json:"matched-at"`
			ExtractedResults []string `json:"extracted-results"`
			Request          string `json:"request"`
			Response         string `json:"response"`
		}

		if err := json.Unmarshal(line, &nRes); err != nil {
			continue
		}

		// 5.6 Output Merging
		res := Result{
			Method:     nRes.Type,
			Path:       nRes.MatchedAt,
			URL:        nRes.MatchedAt,
			StatusCode: 200,
			Labels:     []string{"NUCLEI", nRes.TemplateID},
			Confidence: nRes.Info.Severity,
			Note:       nRes.Info.Description,
		}

		if nRes.Request != "" {
			res.RequestBytes = []byte(nRes.Request)
			res.ResponseBytes = []byte(nRes.Response)
		}

		select {
		case e.Results <- res:
		default:
		}
	}
}
