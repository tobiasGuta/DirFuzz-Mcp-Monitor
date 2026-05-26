package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"

	"dirfuzz/pkg/engine"
)

type swarmChunk struct {
	index int
	lines []string
}

type swarmChunkResult struct {
	index    int
	response engine.SwarmWorkerResponse
}

func runSwarmWorkerCLI() error {
	reqCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var req engine.SwarmWorkerRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return fmt.Errorf("decoding worker request: %w", err)
	}
	resp, err := engine.RunSwarmWorker(reqCtx, req)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(resp)
}

func runSwarm(cfg cliConfig) error {
	if cfg.DryRun {
		eng := engine.NewEngine(cfg.Threads, engine.DefaultBloomFilterSize, engine.DefaultBloomFilterFP)
		defer eng.Shutdown()

		if err := prepareControllerEngine(eng, cfg); err != nil {
			return err
		}

		wordlistPath := cfg.Wordlist
		startLine := int64(0)
		if cfg.Resume {
			var err error
			wordlistPath, startLine, err = loadResumeMetadata(cfg.ResumeFile)
			if err != nil {
				return fmt.Errorf("loading resume state from %s: %w", cfg.ResumeFile, err)
			}
		}

		est, err := eng.EstimateWordlist(wordlistPath, startLine)
		if err != nil {
			return fmt.Errorf("estimating swarm scan: %w", err)
		}
		printDryRunEstimate(cfg, est)
		return nil
	}

	reqCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if !cfg.NoTUI {
		fmt.Fprintf(os.Stderr, "[*] Swarm mode enabled: provider=%s nodes=%d chunk=%d\n", cfg.SwarmProvider, cfg.SwarmNodes, cfg.SwarmChunkSize)
	}

	wordlistPath := cfg.Wordlist
	startLine := int64(0)
	if cfg.Resume {
		var err error
		wordlistPath, startLine, err = loadResumeMetadata(cfg.ResumeFile)
		if err != nil {
			return fmt.Errorf("loading resume state from %s: %w", cfg.ResumeFile, err)
		}
		fmt.Fprintf(os.Stderr, "[*] Resuming %s from line %d\n", wordlistPath, startLine)
	}

	if cfg.SwarmProvider == "" {
		cfg.SwarmProvider = "local"
	}

	provider, err := buildSwarmProvider(reqCtx, cfg)
	if err != nil {
		return err
	}

	workerCfg, err := buildSwarmWorkerConfig(cfg)
	if err != nil {
		return err
	}

	swCtx, cancel := context.WithCancel(reqCtx)
	defer cancel()

	results, warnings, err := executeSwarm(swCtx, cancel, provider, cfg, workerCfg, cfg.Target, wordlistPath, startLine)
	if err != nil {
		return err
	}

	results = engine.AggregateSwarmResults(results, cfg.SimhashThreshold, cfg.SimhashClusterLimit)
	sortResults(results)

	for _, w := range warnings {
		if strings.TrimSpace(w) != "" {
			fmt.Fprintf(os.Stderr, "[swarm] %s\n", w)
		}
	}

	if err := writeSwarmOutput(cfg, results); err != nil {
		return err
	}

	if cfg.HeaderAudit {
		PrintHeaderAuditSummary(RunHeaderAudit(results))
	}
	return writeReportIfRequested(nil, cfg, results)
}

func buildSwarmProvider(ctx context.Context, cfg cliConfig) (engine.SwarmProvider, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.SwarmProvider)) {
	case "", "local":
		return engine.LocalSwarmProvider{}, nil
	case "lambda":
		fn := firstNonEmpty(
			os.Getenv("DIRFUZZ_SWARM_LAMBDA_FUNCTION"),
			os.Getenv("SWARM_LAMBDA_FUNCTION"),
			os.Getenv("AWS_LAMBDA_FUNCTION_NAME"),
		)
		if fn == "" {
			return nil, fmt.Errorf("lambda swarm provider requires DIRFUZZ_SWARM_LAMBDA_FUNCTION, SWARM_LAMBDA_FUNCTION, or AWS_LAMBDA_FUNCTION_NAME")
		}
		return engine.NewLambdaSwarmProvider(ctx, fn)
	default:
		return nil, fmt.Errorf("unsupported swarm provider %q", cfg.SwarmProvider)
	}
}

func buildSwarmWorkerConfig(cfg cliConfig) (engine.SwarmWorkerConfig, error) {
	normalizedAuth, err := normalizeAuthMatrix(cfg.AuthMatrix)
	if err != nil {
		return engine.SwarmWorkerConfig{}, fmt.Errorf("invalid auth matrix: %w", err)
	}

	workerCfg := engine.SwarmWorkerConfig{
		Threads:              cfg.Threads,
		UserAgent:            cfg.UserAgent,
		Headers:              headersToMap(cfg.Headers),
		AuthMatrix:           normalizedAuth,
		MatchCodes:           mustCSVInts(cfg.MatchCodes, "-mc"),
		FilterSizes:          mustCSVInts(cfg.FilterSizes, "-fs"),
		MatchRegex:           cfg.MatchRegex,
		FilterRegex:          cfg.FilterRegex,
		Extensions:           splitTrimmed(cfg.Extensions),
		Methods:              normalizedMethods(splitTrimmed(cfg.Methods)),
		Timeout:              cfg.Timeout,
		Insecure:             cfg.Insecure,
		Delay:                cfg.Delay,
		RPS:                  cfg.RPS,
		FollowRedirects:      cfg.Follow,
		MaxRedirects:         cfg.MaxRedirects,
		RequestBody:          cfg.Body,
		FilterWords:          cfg.FilterWords,
		FilterLines:          cfg.FilterLines,
		MatchWords:           cfg.MatchWords,
		MatchLines:           cfg.MatchLines,
		FilterRTMin:          cfg.RTMin,
		FilterRTMax:          cfg.RTMax,
		ProxyOut:             cfg.ProxyOut,
		SaveRaw:              cfg.SaveRaw,
		AntiBotFallback:      cfg.AntiBotFallback,
		AllowPrivateTargets:  cfg.AllowPrivate,
		Recursive:            cfg.Recursive,
		RecursivePrune:       boolPtr(cfg.RecursivePrune),
		MaxDepth:             cfg.MaxDepth,
		SmartAPI:             cfg.SmartAPI,
		Mutate:               cfg.Mutate,
		AutoFilterThreshold:  cfg.AutoFilterThreshold,
		SimhashThreshold:     cfg.SimhashThreshold,
		SimhashClusterLimit:  cfg.SimhashClusterLimit,
		H2Mode:               cfg.H2Mode,
		H2ConcurrentStreams:  cfg.H2ConcurrentStreams,
		TimingOracle:         cfg.TimingOracle,
		TimeOracleK:          cfg.TimeOracleK,
		TimeOracleN:          cfg.TimeOracleN,
		TimeTrim:             cfg.TimeTrim,
		Harvest:              cfg.Harvest,
		HarvestJS:            cfg.HarvestJS,
		HarvestAPI:           cfg.HarvestAPI,
		HarvestResponse:      cfg.HarvestResponse,
		HarvestResponseDepth: cfg.HarvestResponseDepth,
		HarvestResponseFetch: cfg.HarvestResponseFetch,
		ParamWordlist:        append([]string(nil), cfg.ParamWords...),
		EvasionLimit:         cfg.EvasionLimit,
		MaxRetries:           cfg.MaxRetries,
		VerbTamper:           cfg.VerbTamper,
		FourOhThreeBypass:    cfg.FourOhThreeBypass,
		ProxyFile:            cfg.ProxyFile,
		EagleFile:            cfg.EagleFile,
		PluginMatch:          cfg.PluginMatch,
		PluginMutate:         cfg.PluginMutate,
	}
	if cfg.Cookie != "" {
		if workerCfg.Headers == nil {
			workerCfg.Headers = make(map[string]string, 1)
		}
		workerCfg.Headers["Cookie"] = cfg.Cookie
	}

	return workerCfg, nil
}

func executeSwarm(
	ctx context.Context,
	cancel context.CancelFunc,
	provider engine.SwarmProvider,
	cfg cliConfig,
	workerCfg engine.SwarmWorkerConfig,
	target string,
	wordlistPath string,
	startLine int64,
) ([]engine.Result, []string, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, nil, fmt.Errorf("opening wordlist %s: %w", wordlistPath, err)
	}
	defer file.Close()

	chunkSize := cfg.SwarmChunkSize
	if chunkSize < 1 {
		chunkSize = 1
	}
	nodeCount := cfg.SwarmNodes
	if nodeCount < 1 {
		nodeCount = 1
	}

	chunkCh := make(chan swarmChunk, nodeCount)
	resultCh := make(chan swarmChunkResult, nodeCount)
	errCh := make(chan error, 1)

	go func() {
		defer close(chunkCh)
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		lineNum := int64(0)
		current := make([]string, 0, chunkSize)
		chunkIndex := 0
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			lineNum++
			if lineNum <= startLine {
				continue
			}
			current = append(current, line)
			if len(current) >= chunkSize {
				lines := append([]string(nil), current...)
				select {
				case chunkCh <- swarmChunk{index: chunkIndex, lines: lines}:
					chunkIndex++
				case <-ctx.Done():
					return
				}
				current = current[:0]
			}
		}
		if err := scanner.Err(); err != nil {
			select {
			case errCh <- err:
			default:
			}
			return
		}
		if len(current) > 0 {
			lines := append([]string(nil), current...)
			select {
			case chunkCh <- swarmChunk{index: chunkIndex, lines: lines}:
			case <-ctx.Done():
			}
		}
	}()

	var workers sync.WaitGroup
	for i := 0; i < nodeCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for chunk := range chunkCh {
				resp, err := provider.Invoke(ctx, engine.SwarmWorkerRequest{
					Target:        target,
					WordlistChunk: chunk.lines,
					Config:        workerCfg,
				})
				if err != nil {
					select {
					case errCh <- fmt.Errorf("worker chunk %d: %w", chunk.index, err):
					default:
					}
					return
				}
				select {
				case resultCh <- swarmChunkResult{index: chunk.index, response: resp}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		workers.Wait()
		close(resultCh)
	}()

	var (
		results  []engine.Result
		warnings []string
	)

	for {
		select {
		case err := <-errCh:
			if err != nil {
				cancel()
				return nil, nil, err
			}
		case batch, ok := <-resultCh:
			if !ok {
				return results, warnings, nil
			}
			results = append(results, batch.response.Results...)
			warnings = append(warnings, batch.response.Warnings...)
		case <-ctx.Done():
			return results, warnings, ctx.Err()
		}
	}
}

func writeSwarmOutput(cfg cliConfig, results []engine.Result) error {
	var (
		outFile *os.File
		bufW    *bufio.Writer
		csvW    *csv.Writer
	)

	if cfg.OutputFile != "" {
		f, err := os.OpenFile(cfg.OutputFile, outputFileOpenFlags(cfg.HistoryMode), 0o600)
		if err != nil {
			return fmt.Errorf("creating output file %s: %w", cfg.OutputFile, err)
		}
		defer func() {
			if bufW != nil {
				_ = bufW.Flush()
			}
			if csvW != nil {
				csvW.Flush()
			}
			_ = f.Close()
		}()
		outFile = f

		if cfg.OutputFormat == "csv" {
			csvW = csv.NewWriter(outFile)
			engine.WriteCSVHeader(csvW)
		} else {
			bufW = bufio.NewWriter(outFile)
		}

		for _, res := range results {
			switch cfg.OutputFormat {
			case "csv":
				_ = csvW.Write(res.ToCSV())
			case "url":
				u := res.URL
				if u == "" {
					u = res.Path
				}
				fmt.Fprintln(bufW, u)
			default:
				b, _ := json.Marshal(res)
				_, _ = bufW.Write(b)
				_, _ = bufW.Write([]byte("\n"))
			}
		}
	}

	for _, res := range results {
		if res.IsEagleAlert {
			fmt.Printf("[EAGLE] %s  %d → %d\n", res.Path, res.OldStatusCode, res.StatusCode)
		} else {
			fmt.Println(res.String())
		}
	}
	return nil
}

func loadResumeMetadata(path string) (string, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		return "", 0, err
	}
	wordlist, _ := state["wordlist"].(string)
	lineF, _ := state["line"].(float64)
	return wordlist, int64(lineF), nil
}

func prepareControllerEngine(eng *engine.Engine, cfg cliConfig) error {
	matchCodes := mustCSVInts(cfg.MatchCodes, "-mc")
	filterSizes := mustCSVInts(cfg.FilterSizes, "-fs")
	eng.ConfigureFilters(matchCodes, filterSizes)
	for _, ext := range splitTrimmed(cfg.Extensions) {
		eng.AddExtension(strings.TrimPrefix(ext, "."))
	}
	if cfg.UserAgent != "" {
		eng.UpdateUserAgent(cfg.UserAgent)
	}
	if cfg.Cookie != "" {
		eng.AddHeader("Cookie", cfg.Cookie)
	}
	for _, h := range cfg.Headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			eng.AddHeader(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if cfg.Delay > 0 {
		eng.SetDelay(cfg.Delay)
	}
	if cfg.RPS > 0 {
		eng.SetRPS(cfg.RPS)
	}
	if cfg.Follow {
		eng.SetFollowRedirects(true)
	}
	if normalized, err := normalizeAuthMatrix(cfg.AuthMatrix); err != nil {
		return fmt.Errorf("invalid auth matrix: %w", err)
	} else {
		cfg.AuthMatrix = normalized
	}

	eng.UpdateConfig(func(c *engine.Config) {
		c.Timeout = cfg.Timeout
		c.Insecure = cfg.Insecure
		c.MaxRedirects = cfg.MaxRedirects
		c.RequestBody = cfg.Body
		c.SaveRaw = cfg.SaveRaw
		c.AuthMatrix = cfg.AuthMatrix
		c.Recursive = cfg.Recursive
		c.RecursivePrune = cfg.RecursivePrune
		c.MaxDepth = cfg.MaxDepth
		c.SmartAPI = cfg.SmartAPI
		c.Mutate = cfg.Mutate
		c.FilterWords = cfg.FilterWords
		c.FilterLines = cfg.FilterLines
		c.MatchWords = cfg.MatchWords
		c.MatchLines = cfg.MatchLines
		c.FilterRTMin = cfg.RTMin
		c.FilterRTMax = cfg.RTMax
		c.ProxyOut = cfg.ProxyOut
		c.AutoFilterThreshold = cfg.AutoFilterThreshold
		c.SimhashThreshold = cfg.SimhashThreshold
		c.SimhashClusterLimit = cfg.SimhashClusterLimit
		c.H2Mode = cfg.H2Mode
		c.H2ConcurrentStreams = cfg.H2ConcurrentStreams
		c.TimingOracle = cfg.TimingOracle
		c.TimeOracleK = cfg.TimeOracleK
		c.TimeOracleN = cfg.TimeOracleN
		c.TimeTrim = cfg.TimeTrim
		c.Harvest = cfg.Harvest
		c.HarvestJS = cfg.HarvestJS
		c.HarvestAPI = cfg.HarvestAPI
		c.HarvestResponse = cfg.HarvestResponse
		c.HarvestPassive = cfg.HarvestPassive
		c.HarvestSourceMaps = cfg.HarvestSourceMaps
		c.HarvestResponseDepth = cfg.HarvestResponseDepth
		c.HarvestResponseFetch = cfg.HarvestResponseFetch
		c.HarvestOTXKey = cfg.HarvestOTXKey
		c.ParamWordlist = append([]string(nil), cfg.ParamWords...)
		c.EvasionLimit = cfg.EvasionLimit
		c.MaxRetries = cfg.MaxRetries
		c.VerbTamper = cfg.VerbTamper
		c.FourOhThreeBypass = cfg.FourOhThreeBypass
		c.AntiBotFallback = cfg.AntiBotFallback
		c.AllowPrivateTargets = cfg.AllowPrivate
		if cfg.OutputFile != "" {
			c.OutputFile = cfg.OutputFile
			c.OutputFormat = cfg.OutputFormat
		}
		for _, m := range splitTrimmed(cfg.Methods) {
			c.Methods = append(c.Methods, strings.ToUpper(m))
		}
	})

	if cfg.MatchRegex != "" {
		if err := eng.SetMatchRegex(cfg.MatchRegex); err != nil {
			return fmt.Errorf("invalid -mr regex: %w", err)
		}
	}
	if cfg.FilterRegex != "" {
		if err := eng.SetFilterRegex(cfg.FilterRegex); err != nil {
			return fmt.Errorf("invalid -fr regex: %w", err)
		}
	}

	if cfg.PluginMatch != "" {
		pm, err := engine.NewPluginMatcher(cfg.PluginMatch, cfg.Timeout)
		if err != nil {
			return fmt.Errorf("plugin-match: %w", err)
		}
		defer pm.Close()
		eng.SetMatchPlugin(pm)
	}
	if cfg.PluginMutate != "" {
		pm, err := engine.NewPluginMutator(cfg.PluginMutate, cfg.Timeout)
		if err != nil {
			return fmt.Errorf("plugin-mutate: %w", err)
		}
		defer pm.Close()
		eng.SetMutatePlugin(pm)
	}
	if cfg.ProxyFile != "" {
		if err := eng.LoadProxies(cfg.ProxyFile); err != nil {
			return fmt.Errorf("loading proxy list: %w", err)
		}
	}
	if cfg.OOB {
		eng.UpdateConfig(func(c *engine.Config) {
			c.OOBEnabled = true
			c.InteractshServer = cfg.OOBServer
			c.InteractshToken = cfg.OOBToken
		})
	}
	if cfg.ProxyOut != "" && cfg.Insecure {
		fmt.Fprintf(os.Stderr, "[!] Warning: --proxy-out is using insecure TLS verification because --insecure is enabled\n")
	}
	if cfg.EagleFile != "" {
		if err := eng.LoadPreviousScan(cfg.EagleFile); err != nil {
			return fmt.Errorf("loading eagle baseline: %w", err)
		}
	}
	if cfg.H2Mode && cfg.ProxyFile != "" {
		return fmt.Errorf("--h2 cannot be used together with --proxy")
	}
	if err := eng.SetTarget(cfg.Target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	return nil
}

func headersToMap(headers []string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for _, h := range headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}

func normalizedMethods(methods []string) []string {
	if len(methods) == 0 {
		return nil
	}
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, strings.ToUpper(m))
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
