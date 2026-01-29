package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "yubikey-kube-proxy",
	Short: "A proxy for Kubernetes authentication using YubiKey",
	Long: `yubikey-kube-proxy secures your Kubernetes client certificates by storing
them on a YubiKey. It provides three main functions:

1. setup: Extract certificates from a kubeconfig, import them to your YubiKey,
   and generate new kubeconfig files that use the proxy.

2. proxy: Run a local proxy that handles mTLS authentication using the
   certificates stored on your YubiKey.

3. shell: Start an interactive shell session with the proxy running in the
   background. When you exit the shell, the proxy terminates.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(shellCmd)
}
