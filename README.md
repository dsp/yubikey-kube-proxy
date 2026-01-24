# yubikey-kube-proxy

A local proxy for Kubernetes authentication using YubiKey PIV. Store your Kubernetes client certificates securely on a YubiKey - the private key never leaves the hardware token.

## Why?

Kubernetes client certificates stored in kubeconfig files are a security risk - they're often plaintext on disk. This tool:

1. Imports your client certificate and key to a YubiKey
2. Runs a local proxy that uses the YubiKey for mTLS authentication
3. Your private key never leaves the YubiKey

## Installation

### NixOS (Flake)

```nix
# flake.nix
{
  inputs.yubikey-kube-proxy.url = "github:dsp/yubikey-kube-proxy";
}

# configuration.nix
{ inputs, ... }: {
  imports = [ inputs.yubikey-kube-proxy.nixosModules.default ];
  programs.yubikey-kube-proxy.enable = true;
}
```

This automatically enables `pcscd` (required for YubiKey access).

### From Source

```bash
# Requires libpcsclite-dev and Go 1.21+
go install github.com/dsp/yubikey-kube-proxy@latest
```

### Nix (ad-hoc)

```bash
nix run github:dsp/yubikey-kube-proxy -- --help
```

## Usage

### 1. Import certificates to YubiKey

```bash
yubikey-kube-proxy setup --kubeconfig=~/.kube/config --context=my-cluster
```

This will:
- Extract client cert/key from your kubeconfig
- Import them to YubiKey slot 9a (authentication) via `ykman`
- Generate a new kubeconfig pointing to the local proxy

### 2. Start the proxy

```bash
yubikey-kube-proxy proxy --kubeconfig=~/.kube/config --context=my-cluster
```

You'll be prompted for your YubiKey PIN. The proxy listens on `localhost:8080`.

### 3. Use kubectl

```bash
export KUBECONFIG=./my-cluster-yubikey.kubeconfig
kubectl get pods
```

## Options

### setup

| Flag | Default | Description |
|------|---------|-------------|
| `--kubeconfig` | `$KUBECONFIG` or `~/.kube/config` | Input kubeconfig |
| `--context` | current-context | Context to extract |
| `--slot` | `9a` | YubiKey PIV slot (9a, 9c, 9d, 9e) |
| `--output-dir` | `.` | Output directory for new kubeconfig |
| `--proxy-port` | `8080` | Port for proxy |

### proxy

| Flag | Default | Description |
|------|---------|-------------|
| `--kubeconfig` | `$KUBECONFIG` or `~/.kube/config` | Kubeconfig with server/CA info |
| `--context` | current-context | Context to use |
| `--slot` | `9a` | YubiKey PIV slot |
| `--port` | `8080` | Port to listen on |

## PIV Slots

| Slot | Name | Typical Use |
|------|------|-------------|
| 9a | Authentication | General purpose (recommended) |
| 9c | Digital Signature | Code/document signing |
| 9d | Key Management | Encryption |
| 9e | Card Authentication | Physical access |

## Requirements

- YubiKey with PIV support (YubiKey 4/5 series)
- `ykman` (yubikey-manager) for setup
- `pcscd` service running (for YubiKey access)

## Security

- Private keys never leave the YubiKey hardware
- PIN required for signing operations
- Proxy binds to localhost only
- Temp files created with 0600 permissions and cleaned up

## License

MIT
