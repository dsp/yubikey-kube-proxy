package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"

	"github.com/go-piv/piv-go/piv"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	proxyKubeconfig string
	proxyContext    string
	proxyPort       int
	proxySlot       string
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
}

func runProxy(cmd *cobra.Command, args []string) error {
	// Validate port range
	if proxyPort < 1 || proxyPort > 65535 {
		return fmt.Errorf("invalid port %d: must be between 1 and 65535", proxyPort)
	}

	// Load kubeconfig
	kubeconfigPath := proxyKubeconfig
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}

	config, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	// Determine context
	contextName := proxyContext
	if contextName == "" {
		contextName = config.CurrentContext
	}
	if contextName == "" {
		return fmt.Errorf("no context specified and no current-context set")
	}

	ctx, ok := config.Contexts[contextName]
	if !ok {
		return fmt.Errorf("context %q not found in kubeconfig", contextName)
	}

	// Get cluster info
	cluster, ok := config.Clusters[ctx.Cluster]
	if !ok {
		return fmt.Errorf("cluster %q not found for context %q", ctx.Cluster, contextName)
	}

	serverURL, err := url.Parse(cluster.Server)
	if err != nil {
		return fmt.Errorf("failed to parse server URL %q: %w", cluster.Server, err)
	}

	if serverURL.Scheme != "https" {
		return fmt.Errorf("server URL must use HTTPS, got %q", cluster.Server)
	}

	// Build CA cert pool
	var caCertPool *x509.CertPool
	if len(cluster.CertificateAuthorityData) > 0 {
		caCertPool = x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(cluster.CertificateAuthorityData) {
			return fmt.Errorf("failed to parse CA certificate data")
		}
	} else if cluster.CertificateAuthority != "" {
		caPath := cluster.CertificateAuthority
		if !filepath.IsAbs(caPath) {
			caPath = filepath.Join(filepath.Dir(kubeconfigPath), caPath)
		}
		caData, err := os.ReadFile(caPath)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate from %s: %w", caPath, err)
		}
		caCertPool = x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caData) {
			return fmt.Errorf("failed to parse CA certificate from %s", caPath)
		}
	} else if !cluster.InsecureSkipTLSVerify {
		// Use system CA pool
		caCertPool, err = x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("failed to load system CA pool: %w", err)
		}
	}

	// Open YubiKey
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("failed to enumerate smart cards: %w", err)
	}
	if len(cards) == 0 {
		return fmt.Errorf("no YubiKey found - please insert your YubiKey")
	}

	yk, err := piv.Open(cards[0])
	if err != nil {
		return fmt.Errorf("failed to open YubiKey: %w", err)
	}
	defer yk.Close()

	// Map slot string to piv.Slot
	slot, err := parseSlot(proxySlot)
	if err != nil {
		return err
	}

	// Get certificate from YubiKey
	cert, err := yk.Certificate(slot)
	if err != nil {
		return fmt.Errorf("failed to get certificate from YubiKey slot %s: %w", proxySlot, err)
	}

	// Get private key handle (YubiKey as crypto oracle)
	// We use PINPolicyNever since the key is imported with touch-only policy.
	// This also skips attestation-based policy detection which fails for imported keys.
	priv, err := yk.PrivateKey(slot, cert.PublicKey, piv.KeyAuth{
		PINPolicy: piv.PINPolicyNever,
	})
	if err != nil {
		return fmt.Errorf("failed to get private key handle from YubiKey: %w", err)
	}

	// Create TLS config with YubiKey-backed client certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  priv,
			},
		},
		RootCAs:            caCertPool,
		InsecureSkipVerify: cluster.InsecureSkipTLSVerify,
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(serverURL)
	proxy.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Modify the director to update the host header
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = serverURL.Host
	}

	// Start server
	addr := fmt.Sprintf("localhost:%d", proxyPort)
	log.Printf("Starting proxy on %s -> %s", addr, cluster.Server)
	log.Printf("Using YubiKey certificate from slot %s (touch required for each request)", proxySlot)
	log.Printf("Press Ctrl+C to stop")

	return http.ListenAndServe(addr, proxy)
}

func parseSlot(s string) (piv.Slot, error) {
	switch s {
	case "9a":
		return piv.SlotAuthentication, nil
	case "9c":
		return piv.SlotSignature, nil
	case "9d":
		return piv.SlotKeyManagement, nil
	case "9e":
		return piv.SlotCardAuthentication, nil
	default:
		return piv.Slot{}, fmt.Errorf("unknown PIV slot %q (valid: 9a, 9c, 9d, 9e)", s)
	}
}

