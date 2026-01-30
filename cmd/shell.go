package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/dsp/yubikey-kube-proxy/internal/proxy"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	shellKubeconfig   string
	shellContext      string
	shellPort         int
	shellSlot         string
	shellKeepAlives   bool
	shellClientConfig string
)

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Start a shell session with YubiKey-backed Kubernetes access",
	Long: `Shell starts a local proxy using your YubiKey for authentication and spawns
an interactive shell with KUBECONFIG set to use the proxy.

When you exit the shell, the proxy automatically terminates.

Environment variables set in the shell:
  YUBIKEY_KUBE_PROXY_ACTIVE=1    - Indicates you're in a yubikey-kube-proxy shell
  YUBIKEY_KUBE_CONTEXT=<context> - The Kubernetes context name

You can use these in your shell prompt to indicate when you're in a YubiKey session.

Example:
  yubikey-kube-proxy shell --kubeconfig=proxy.yml --client-config=client.yml`,
	RunE:         runShell,
	SilenceUsage: true, // Don't print usage on shell exit errors
}

func init() {
	shellCmd.Flags().StringVar(&shellKubeconfig, "kubeconfig", "", "Path to proxy kubeconfig file (contains server/CA info)")
	shellCmd.Flags().StringVar(&shellContext, "context", "", "Context to use (default: current-context)")
	shellCmd.Flags().IntVar(&shellPort, "port", 8080, "Port for the local proxy")
	shellCmd.Flags().StringVar(&shellSlot, "slot", "9a", "YubiKey PIV slot containing the certificate")
	shellCmd.Flags().BoolVar(&shellKeepAlives, "keep-alives", false, "Enable HTTP keep-alives")
	shellCmd.Flags().StringVar(&shellClientConfig, "client-config", "", "Path to client kubeconfig (default: client.yml in same dir as kubeconfig)")
}

func runShell(cmd *cobra.Command, args []string) error {
	// Check for nested shell - prevent starting shell inside shell
	if os.Getenv("YUBIKEY_KUBE_PROXY_ACTIVE") == "1" {
		return fmt.Errorf("already running inside a yubikey-kube-proxy shell (detected YUBIKEY_KUBE_PROXY_ACTIVE=1)")
	}

	// Validate port range
	if shellPort < 1 || shellPort > 65535 {
		return fmt.Errorf("invalid port %d: must be between 1 and 65535", shellPort)
	}

	// Load kubeconfig
	loadedConfig, err := proxy.LoadKubeconfig(shellKubeconfig, shellContext)
	if err != nil {
		return err
	}

	// Determine client config path early (before opening YubiKey)
	clientConfigPath := shellClientConfig
	if clientConfigPath == "" {
		kubeconfigPath := shellKubeconfig
		if kubeconfigPath == "" {
			kubeconfigPath = os.Getenv("KUBECONFIG")
		}
		if kubeconfigPath == "" {
			home, _ := os.UserHomeDir()
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
		clientConfigPath = filepath.Join(filepath.Dir(kubeconfigPath), "client.yml")
	}

	// Check client config exists before we open the YubiKey
	if _, err := os.Stat(clientConfigPath); os.IsNotExist(err) {
		return fmt.Errorf("client config not found at %s - run 'setup' first or specify --client-config", clientConfigPath)
	}

	// Make path absolute for the shell environment
	clientConfigPath, err = filepath.Abs(clientConfigPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for client config: %w", err)
	}

	// Open YubiKey and get credentials
	creds, err := proxy.OpenYubiKey(shellSlot)
	if err != nil {
		return err
	}
	defer creds.YK.Close()

	// Log security warnings
	proxy.LogSecurityWarnings(loadedConfig.InsecureSkipTLSVerify, shellKeepAlives)

	// Create TLS config and reverse proxy
	tlsConfig := proxy.CreateTLSConfig(creds, loadedConfig.CACertPool, loadedConfig.InsecureSkipTLSVerify)
	reverseProxy := proxy.CreateReverseProxy(loadedConfig.ServerURL, tlsConfig, shellKeepAlives)

	// Create server with explicit listener for clean shutdown
	addr := fmt.Sprintf("localhost:%d", shellPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	server := &http.Server{
		Handler: reverseProxy,
	}

	// Track server errors
	serverErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Check for immediate server failure
	select {
	case err := <-serverErr:
		if err != nil {
			return fmt.Errorf("proxy server failed to start: %w", err)
		}
		return fmt.Errorf("proxy server exited unexpectedly")
	case <-time.After(50 * time.Millisecond):
		// Server started successfully
	}

	log.Printf("Proxy started on %s -> %s", addr, loadedConfig.ServerURL)
	log.Printf("Using YubiKey certificate from slot %s", shellSlot)

	// Set terminal title (only if we're in a real terminal)
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))
	if isTTY {
		fmt.Printf("\033]0;yk-kube: %s\007", loadedConfig.ContextName)
	}

	// Get user's shell
	userShell := os.Getenv("SHELL")
	if userShell == "" {
		userShell = "/bin/sh"
	}

	// Verify shell exists and is executable
	if _, err := exec.LookPath(userShell); err != nil {
		shutdownServer(server)
		return fmt.Errorf("shell %q not found or not executable: %w", userShell, err)
	}

	// Prepare shell command
	shellExec := exec.Command(userShell)
	shellExec.Stdin = os.Stdin
	shellExec.Stdout = os.Stdout
	shellExec.Stderr = os.Stderr
	shellExec.Env = append(os.Environ(),
		"KUBECONFIG="+clientConfigPath,
		"YUBIKEY_KUBE_PROXY_ACTIVE=1",
		"YUBIKEY_KUBE_CONTEXT="+loadedConfig.ContextName,
	)

	// Start the shell first (so Process is set before signal handler runs)
	log.Printf("Starting shell (exit to terminate proxy)")
	fmt.Println()

	if err := shellExec.Start(); err != nil {
		shutdownServer(server)
		if isTTY {
			fmt.Printf("\033]0;\007") // Restore terminal title
		}
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// Now set up signal forwarding (Process is guaranteed to be non-nil)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var sigWg sync.WaitGroup
	sigWg.Add(1)
	go func() {
		defer sigWg.Done()
		for sig := range sigChan {
			// Process is set since we called Start() before setting up this handler
			// Use a goroutine-safe check in case process has exited
			if shellExec.Process != nil {
				_ = shellExec.Process.Signal(sig) // Ignore error if process already exited
			}
		}
	}()

	// Wait for shell to exit
	shellErr := shellExec.Wait()

	// Clean up signal handler
	signal.Stop(sigChan)
	close(sigChan)
	sigWg.Wait()

	// Restore terminal title
	if isTTY {
		fmt.Printf("\033]0;\007")
	}

	// Shutdown proxy
	log.Printf("Shell exited, shutting down proxy...")
	shutdownServer(server)

	// Check for server errors (non-blocking since we already shut down)
	select {
	case err := <-serverErr:
		if err != nil {
			log.Printf("Proxy server error: %v", err)
		}
	default:
	}

	// Handle shell exit
	if shellErr != nil {
		if exitErr, ok := shellErr.(*exec.ExitError); ok {
			// Shell exited with non-zero status - this is normal (e.g., last command failed)
			// Exit silently with the same code
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("shell error: %w", shellErr)
	}

	return nil
}

// shutdownServer gracefully shuts down the HTTP server with a timeout
func shutdownServer(server *http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error shutting down proxy: %v", err)
	}
}
