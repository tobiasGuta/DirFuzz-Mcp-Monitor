package launcher

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Launcher struct {
	headless  bool
	noSandbox bool
	cmd       *exec.Cmd
	port      int
	userDir   string
}

func New() *Launcher {
	return &Launcher{headless: true}
}

func (l *Launcher) Headless(enable bool) *Launcher {
	l.headless = enable
	return l
}

func (l *Launcher) NoSandbox(enable bool) *Launcher {
	l.noSandbox = enable
	return l
}

func (l *Launcher) Launch() (string, error) {
	if l == nil {
		return "", fmt.Errorf("launcher is nil")
	}
	bin, err := findBrowserBinary()
	if err != nil {
		return "", err
	}

	port, err := freePort()
	if err != nil {
		return "", err
	}
	l.port = port

	userDir, err := os.MkdirTemp("", "rod-user-data-*")
	if err != nil {
		return "", err
	}
	l.userDir = userDir

	args := []string{
		fmt.Sprintf("--remote-debugging-port=%d", port),
		fmt.Sprintf("--user-data-dir=%s", userDir),
		"--disable-background-networking",
		"--disable-default-apps",
		"--disable-dev-shm-usage",
		"--disable-extensions",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-popup-blocking",
	}
	if l.headless {
		args = append(args, "--headless=new")
	}
	if l.noSandbox {
		args = append(args, "--no-sandbox")
	}
	args = append(args, "about:blank")

	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(userDir)
		return "", err
	}
	l.cmd = cmd

	controlURL, err := waitForDevToolsURL(port, 20*time.Second)
	if err != nil {
		_ = l.Kill()
		return "", err
	}
	return controlURL, nil
}

func (l *Launcher) MustLaunch() string {
	u, err := l.Launch()
	if err != nil {
		panic(err)
	}
	return u
}

func (l *Launcher) Cleanup() {
	_ = l.Kill()
}

func (l *Launcher) Kill() error {
	if l == nil {
		return nil
	}
	if l.cmd != nil && l.cmd.Process != nil {
		_ = l.cmd.Process.Kill()
		_, _ = l.cmd.Process.Wait()
		l.cmd = nil
	}
	if l.userDir != "" {
		_ = os.RemoveAll(l.userDir)
		l.userDir = ""
	}
	return nil
}

func findBrowserBinary() (string, error) {
	if bin := strings.TrimSpace(os.Getenv("ROD_BROWSER_BIN")); bin != "" {
		return bin, nil
	}
	if bin := strings.TrimSpace(os.Getenv("CHROME_BIN")); bin != "" {
		return bin, nil
	}

	candidates := []string{
		"google-chrome",
		"chrome",
		"chromium",
		"chromium-browser",
		"msedge",
		"chrome.exe",
		"msedge.exe",
	}
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}

	if runtime.GOOS == "windows" {
		paths := []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		}
		for _, p := range paths {
			if p == "" {
				continue
			}
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}

	return "", fmt.Errorf("unable to locate a Chrome/Edge binary; set ROD_BROWSER_BIN")
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func waitForDevToolsURL(port int, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/json/version", port)
	for time.Now().Before(deadline) {
		resp, err := http.Get(endpoint)
		if err == nil {
			var payload struct {
				WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
			}
			if decodeErr := json.NewDecoder(resp.Body).Decode(&payload); decodeErr == nil && payload.WebSocketDebuggerURL != "" {
				_ = resp.Body.Close()
				return payload.WebSocketDebuggerURL, nil
			}
			_ = resp.Body.Close()
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", fmt.Errorf("timed out waiting for Chrome DevTools on port %d", port)
}
