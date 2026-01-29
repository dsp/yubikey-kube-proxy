// Package proxy provides shared functionality for the YubiKey Kubernetes proxy.
package proxy

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/go-piv/piv-go/piv"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// Config holds the configuration needed to run the proxy.
type Config struct {
	// KubeconfigPath is the path to the kubeconfig file
	KubeconfigPath string
	// ContextName is the Kubernetes context to use
	ContextName string
	// Slot is the YubiKey PIV slot (e.g., "9a")
	Slot string
	// KeepAlives enables HTTP keep-alives
	KeepAlives bool
}

// LoadedConfig contains the parsed configuration from kubeconfig.
type LoadedConfig struct {
	// ServerURL is the Kubernetes API server URL
	ServerURL *url.URL
	// CACertPool is the CA certificate pool for TLS verification
	CACertPool *x509.CertPool
	// InsecureSkipTLSVerify indicates whether to skip TLS verification
	InsecureSkipTLSVerify bool
	// ContextName is the resolved context name
	ContextName string
}

// YubiKeyCredentials holds the credentials obtained from a YubiKey.
type YubiKeyCredentials struct {
	// YK is the YubiKey handle (caller must close)
	YK *piv.YubiKey
	// Certificate is the client certificate
	Certificate *x509.Certificate
	// PrivateKey is the private key handle (signs using YubiKey)
	PrivateKey crypto.PrivateKey
}

// LoadKubeconfig loads and validates the kubeconfig file.
func LoadKubeconfig(kubeconfigPath, contextName string) (*LoadedConfig, error) {
	// Resolve kubeconfig path
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}

	config, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	// Resolve context
	if contextName == "" {
		contextName = config.CurrentContext
	}
	if contextName == "" {
		return nil, fmt.Errorf("no context specified and no current-context set")
	}

	ctx, ok := config.Contexts[contextName]
	if !ok {
		return nil, fmt.Errorf("context %q not found in kubeconfig", contextName)
	}

	// Get cluster info
	cluster, ok := config.Clusters[ctx.Cluster]
	if !ok {
		return nil, fmt.Errorf("cluster %q not found for context %q", ctx.Cluster, contextName)
	}

	serverURL, err := url.Parse(cluster.Server)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server URL %q: %w", cluster.Server, err)
	}

	if serverURL.Scheme != "https" {
		return nil, fmt.Errorf("server URL must use HTTPS, got %q", cluster.Server)
	}

	// Build CA cert pool
	caCertPool, err := buildCACertPool(cluster, kubeconfigPath)
	if err != nil {
		return nil, err
	}

	return &LoadedConfig{
		ServerURL:             serverURL,
		CACertPool:            caCertPool,
		InsecureSkipTLSVerify: cluster.InsecureSkipTLSVerify,
		ContextName:           contextName,
	}, nil
}

// buildCACertPool builds the CA certificate pool from cluster config.
func buildCACertPool(cluster *api.Cluster, kubeconfigPath string) (*x509.CertPool, error) {
	if len(cluster.CertificateAuthorityData) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cluster.CertificateAuthorityData) {
			return nil, fmt.Errorf("failed to parse CA certificate data")
		}
		return pool, nil
	}

	if cluster.CertificateAuthority != "" {
		caPath := cluster.CertificateAuthority
		if !filepath.IsAbs(caPath) {
			caPath = filepath.Join(filepath.Dir(kubeconfigPath), caPath)
		}
		caData, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caPath)
		}
		return pool, nil
	}

	if !cluster.InsecureSkipTLSVerify {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system CA pool: %w", err)
		}
		return pool, nil
	}

	return nil, nil
}

// OpenYubiKey opens the YubiKey and retrieves credentials from the specified slot.
// The caller is responsible for closing the returned YubiKey handle.
func OpenYubiKey(slotStr string) (*YubiKeyCredentials, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate smart cards: %w", err)
	}
	if len(cards) == 0 {
		return nil, fmt.Errorf("no YubiKey found - please insert your YubiKey")
	}

	yk, err := piv.Open(cards[0])
	if err != nil {
		return nil, fmt.Errorf("failed to open YubiKey: %w", err)
	}

	slot, err := ParseSlot(slotStr)
	if err != nil {
		yk.Close()
		return nil, err
	}

	cert, err := yk.Certificate(slot)
	if err != nil {
		yk.Close()
		return nil, fmt.Errorf("failed to get certificate from YubiKey slot %s: %w", slotStr, err)
	}

	// Get private key handle (YubiKey as crypto oracle)
	// We use PINPolicyNever since the key is imported without PIN requirement.
	priv, err := yk.PrivateKey(slot, cert.PublicKey, piv.KeyAuth{
		PINPolicy: piv.PINPolicyNever,
	})
	if err != nil {
		yk.Close()
		return nil, fmt.Errorf("failed to get private key handle from YubiKey: %w", err)
	}

	return &YubiKeyCredentials{
		YK:          yk,
		Certificate: cert,
		PrivateKey:  priv,
	}, nil
}

// ParseSlot converts a slot string to a piv.Slot.
func ParseSlot(s string) (piv.Slot, error) {
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

// CreateTLSConfig creates a TLS configuration using the YubiKey credentials.
func CreateTLSConfig(creds *YubiKeyCredentials, caCertPool *x509.CertPool, insecureSkipVerify bool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{creds.Certificate.Raw},
				PrivateKey:  creds.PrivateKey,
			},
		},
		RootCAs:            caCertPool,
		InsecureSkipVerify: insecureSkipVerify,
	}
}

// CreateReverseProxy creates an HTTP reverse proxy to the Kubernetes API server.
func CreateReverseProxy(serverURL *url.URL, tlsConfig *tls.Config, keepAlives bool) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(serverURL)
	proxy.Transport = &http.Transport{
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableKeepAlives:     !keepAlives,
	}

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = serverURL.Host
	}

	return proxy
}

// LogSecurityWarnings logs warnings about security-sensitive configuration.
func LogSecurityWarnings(insecureSkipTLSVerify, keepAlives bool) {
	if insecureSkipTLSVerify {
		log.Printf("WARNING: TLS certificate verification is disabled (insecure-skip-tls-verify)")
	}
	if keepAlives {
		log.Printf("WARNING: Keep-alives enabled - YubiKey removal won't immediately revoke access")
	}
}
