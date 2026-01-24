package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

var (
	setupKubeconfig string
	setupContext    string
	setupSlot       string
	setupOutputDir  string
	setupProxyPort  int
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Extract certs from kubeconfig and import to YubiKey",
	Long: `Setup extracts client certificates from an existing kubeconfig file,
imports them to your YubiKey using ykman, and generates a new kubeconfig
that routes through the local proxy.

Example:
  yubikey-kube-proxy setup --kubeconfig=~/.kube/config --context=my-cluster`,
	RunE: runSetup,
}

func init() {
	setupCmd.Flags().StringVar(&setupKubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	setupCmd.Flags().StringVar(&setupContext, "context", "", "Context to extract certificates from (default: current-context)")
	setupCmd.Flags().StringVar(&setupSlot, "slot", "9a", "YubiKey PIV slot to import certificates to")
	setupCmd.Flags().StringVar(&setupOutputDir, "output-dir", ".", "Output directory for kubeconfig files")
	setupCmd.Flags().IntVar(&setupProxyPort, "proxy-port", 8080, "Port the proxy will listen on")
}

func runSetup(cmd *cobra.Command, args []string) error {
	// Validate slot upfront
	if _, err := parseSlot(setupSlot); err != nil {
		return err
	}

	// Validate port range
	if setupProxyPort < 1 || setupProxyPort > 65535 {
		return fmt.Errorf("invalid port %d: must be between 1 and 65535", setupProxyPort)
	}

	// Load kubeconfig
	kubeconfigPath := setupKubeconfig
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
	contextName := setupContext
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

	// Get auth info
	authInfo, ok := config.AuthInfos[ctx.AuthInfo]
	if !ok {
		return fmt.Errorf("auth info %q not found for context %q", ctx.AuthInfo, contextName)
	}

	// Get cluster info
	cluster, ok := config.Clusters[ctx.Cluster]
	if !ok {
		return fmt.Errorf("cluster %q not found for context %q", ctx.Cluster, contextName)
	}

	// Extract certificates
	certData, keyData, err := extractCertificates(authInfo, kubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to extract certificates: %w", err)
	}

	// Check ykman is available
	if _, err := exec.LookPath("ykman"); err != nil {
		return fmt.Errorf("ykman not found in PATH - please install yubikey-manager")
	}

	// Write temp files for ykman
	tmpDir, err := os.MkdirTemp("", "yubikey-kube-proxy")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certData, 0600); err != nil {
		return fmt.Errorf("failed to write temp cert file: %w", err)
	}
	if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
		return fmt.Errorf("failed to write temp key file: %w", err)
	}

	// Import key to YubiKey (no PIN, no touch required)
	fmt.Fprintf(os.Stderr, "Importing private key to YubiKey slot %s...\n", setupSlot)
	importKeyCmd := exec.Command("ykman", "piv", "keys", "import",
		"--pin-policy=never",
		"--touch-policy=never",
		setupSlot, keyFile)
	importKeyCmd.Stdin = os.Stdin
	importKeyCmd.Stdout = os.Stderr
	importKeyCmd.Stderr = os.Stderr
	if err := importKeyCmd.Run(); err != nil {
		return fmt.Errorf("failed to import key to YubiKey: %w", err)
	}

	// Import certificate to YubiKey
	fmt.Fprintf(os.Stderr, "Importing certificate to YubiKey slot %s...\n", setupSlot)
	importCertCmd := exec.Command("ykman", "piv", "certificates", "import", setupSlot, certFile)
	importCertCmd.Stdin = os.Stdin
	importCertCmd.Stdout = os.Stderr
	importCertCmd.Stderr = os.Stderr
	if err := importCertCmd.Run(); err != nil {
		return fmt.Errorf("failed to import certificate to YubiKey: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Successfully imported certificates to YubiKey!\n\n")

	// Generate proxy.yml - redacted version of original (server + CA, no client certs)
	proxyConfig := generateRedactedProxyConfig(config, contextName)
	proxyOutput, err := clientcmd.Write(*proxyConfig)
	if err != nil {
		return fmt.Errorf("failed to serialize proxy kubeconfig: %w", err)
	}

	proxyPath := filepath.Join(setupOutputDir, "proxy.yml")
	if err := os.WriteFile(proxyPath, proxyOutput, 0600); err != nil {
		return fmt.Errorf("failed to write proxy kubeconfig: %w", err)
	}

	// Generate client.yml - points to localhost proxy
	clientConfig := generateProxyKubeconfig(config, contextName, cluster, setupProxyPort)
	clientOutput, err := clientcmd.Write(*clientConfig)
	if err != nil {
		return fmt.Errorf("failed to serialize client kubeconfig: %w", err)
	}

	clientPath := filepath.Join(setupOutputDir, "client.yml")
	if err := os.WriteFile(clientPath, clientOutput, 0600); err != nil {
		return fmt.Errorf("failed to write client kubeconfig: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Created kubeconfig files:\n")
	fmt.Fprintf(os.Stderr, "  %s - for the proxy (server + CA, no client certs)\n", proxyPath)
	fmt.Fprintf(os.Stderr, "  %s - for kubectl (points to localhost:%d)\n", clientPath, setupProxyPort)

	fmt.Fprintf(os.Stderr, "\nTo use:\n")
	fmt.Fprintf(os.Stderr, "  1. Start the proxy:\n")
	fmt.Fprintf(os.Stderr, "     yubikey-kube-proxy proxy --kubeconfig=%s\n", proxyPath)
	fmt.Fprintf(os.Stderr, "  2. Use kubectl with the client config:\n")
	fmt.Fprintf(os.Stderr, "     KUBECONFIG=%s kubectl get nodes\n", clientPath)

	return nil
}

func extractCertificates(authInfo *api.AuthInfo, kubeconfigPath string) (certPEM, keyPEM []byte, err error) {
	kubeconfigDir := filepath.Dir(kubeconfigPath)

	// Try embedded data first
	if len(authInfo.ClientCertificateData) > 0 {
		certPEM = authInfo.ClientCertificateData
	} else if authInfo.ClientCertificate != "" {
		certPath := authInfo.ClientCertificate
		if !filepath.IsAbs(certPath) {
			certPath = filepath.Join(kubeconfigDir, certPath)
		}
		certPEM, err = os.ReadFile(certPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read client certificate from %s: %w", certPath, err)
		}
	} else {
		return nil, nil, fmt.Errorf("no client certificate found in auth info")
	}

	if len(authInfo.ClientKeyData) > 0 {
		keyPEM = authInfo.ClientKeyData
	} else if authInfo.ClientKey != "" {
		keyPath := authInfo.ClientKey
		if !filepath.IsAbs(keyPath) {
			keyPath = filepath.Join(kubeconfigDir, keyPath)
		}
		keyPEM, err = os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read client key from %s: %w", keyPath, err)
		}
	} else {
		return nil, nil, fmt.Errorf("no client key found in auth info")
	}

	return certPEM, keyPEM, nil
}

func generateProxyKubeconfig(originalConfig *api.Config, contextName string, cluster *api.Cluster, proxyPort int) *api.Config {
	proxyContextName := contextName + "-yubikey"
	proxyClusterName := contextName + "-yubikey-proxy"

	newConfig := api.NewConfig()
	newConfig.CurrentContext = proxyContextName

	// Create a cluster entry that points to the proxy
	newConfig.Clusters[proxyClusterName] = &api.Cluster{
		Server: fmt.Sprintf("http://localhost:%d", proxyPort),
	}

	// Create a minimal auth info (proxy handles auth)
	newConfig.AuthInfos[proxyContextName] = &api.AuthInfo{}

	// Create context
	newConfig.Contexts[proxyContextName] = &api.Context{
		Cluster:  proxyClusterName,
		AuthInfo: proxyContextName,
	}

	return newConfig
}

func generateRedactedProxyConfig(originalConfig *api.Config, contextName string) *api.Config {
	ctx := originalConfig.Contexts[contextName]

	newConfig := api.NewConfig()
	newConfig.CurrentContext = contextName

	// Copy cluster info (server + CA) but keep it intact
	originalCluster := originalConfig.Clusters[ctx.Cluster]
	newConfig.Clusters[ctx.Cluster] = &api.Cluster{
		Server:                   originalCluster.Server,
		CertificateAuthority:     originalCluster.CertificateAuthority,
		CertificateAuthorityData: originalCluster.CertificateAuthorityData,
		InsecureSkipTLSVerify:    originalCluster.InsecureSkipTLSVerify,
	}

	// Create auth info WITHOUT client cert/key (redacted)
	newConfig.AuthInfos[ctx.AuthInfo] = &api.AuthInfo{}

	// Copy context
	newConfig.Contexts[contextName] = &api.Context{
		Cluster:   ctx.Cluster,
		AuthInfo:  ctx.AuthInfo,
		Namespace: ctx.Namespace,
	}

	return newConfig
}
