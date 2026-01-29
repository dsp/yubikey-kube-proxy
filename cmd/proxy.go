package cmd

import (
	"fmt"
	"log"
	"net/http"

	"github.com/dsp/yubikey-kube-proxy/internal/proxy"
	"github.com/spf13/cobra"
)

var (
	proxyKubeconfig string
	proxyContext    string
	proxyPort       int
	proxySlot       string
	proxyKeepAlives bool
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a local proxy using YubiKey for mTLS",
	Long: `Proxy starts a local HTTP server that forwards requests to the Kubernetes
API server, using the client certificate stored on your YubiKey for authentication.

The proxy reads the server address and CA from your kubeconfig file.

Example:
  yubikey-kube-proxy proxy --kubeconfig=~/.kube/config --context=my-cluster`,
	RunE: runProxy,
}

func init() {
	proxyCmd.Flags().StringVar(&proxyKubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	proxyCmd.Flags().StringVar(&proxyContext, "context", "", "Context to use for server/CA info (default: current-context)")
	proxyCmd.Flags().IntVar(&proxyPort, "port", 8080, "Port to listen on")
	proxyCmd.Flags().StringVar(&proxySlot, "slot", "9a", "YubiKey PIV slot containing the certificate")
	proxyCmd.Flags().BoolVar(&proxyKeepAlives, "keep-alives", false, "Enable HTTP keep-alives (reduces latency but YubiKey removal won't immediately revoke access)")
}

func runProxy(cmd *cobra.Command, args []string) error {
	// Validate port range
	if proxyPort < 1 || proxyPort > 65535 {
		return fmt.Errorf("invalid port %d: must be between 1 and 65535", proxyPort)
	}

	// Load kubeconfig
	loadedConfig, err := proxy.LoadKubeconfig(proxyKubeconfig, proxyContext)
	if err != nil {
		return err
	}

	// Open YubiKey and get credentials
	creds, err := proxy.OpenYubiKey(proxySlot)
	if err != nil {
		return err
	}
	defer creds.YK.Close()

	// Log security warnings
	proxy.LogSecurityWarnings(loadedConfig.InsecureSkipTLSVerify, proxyKeepAlives)

	// Create TLS config and reverse proxy
	tlsConfig := proxy.CreateTLSConfig(creds, loadedConfig.CACertPool, loadedConfig.InsecureSkipTLSVerify)
	reverseProxy := proxy.CreateReverseProxy(loadedConfig.ServerURL, tlsConfig, proxyKeepAlives)

	// Start server
	addr := fmt.Sprintf("localhost:%d", proxyPort)
	log.Printf("Starting proxy on %s -> %s", addr, loadedConfig.ServerURL)
	log.Printf("Using YubiKey certificate from slot %s", proxySlot)
	log.Printf("Press Ctrl+C to stop")

	return http.ListenAndServe(addr, reverseProxy)
}
