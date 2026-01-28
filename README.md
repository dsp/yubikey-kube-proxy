# yubikey-kube-proxy

NOTE: This is an experimental, partially vibe-coded project.

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
yubikey-kube-proxy proxy --kubeconfig=proxy.yml
```

The proxy listens on `localhost:8080`.

### 3. Use kubectl

```bash
KUBECONFIG=./client.yml kubectl get pods
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
| `--keep-alives` | `false` | Enable HTTP keep-alives (faster but YubiKey removal won't immediately revoke access) |

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

### What this protects against

- **Key extraction**: Private keys are stored in YubiKey hardware and cannot be exported. An attacker who compromises your machine cannot steal the key itself.
- **Credential sprawl**: Client certificates don't sit in plaintext kubeconfig files on disk.
- **Offline attacks**: Stolen backups or disk images don't contain usable credentials.

### What this does NOT protect against

- **Local privilege escalation**: Any process on the machine can use the proxy while it's running. The key is imported with `--pin-policy=never --touch-policy=never` to allow unattended operation (e.g., systemd units).
- **Physical access with YubiKey present**: If an attacker has access to your machine while the YubiKey is plugged in, they can use the proxy.
- **Local network sniffing**: The proxy accepts plain HTTP on localhost. Other local processes could potentially observe traffic between kubectl and the proxy.

### Threat model

This tool is designed for trusted workstations where the primary goal is preventing private key extraction and eliminating plaintext credentials on disk. It assumes:

- Physical security of the machine
- Trust in local processes (or at minimum, that local compromise means game over anyway)
- The YubiKey is removed when not actively needed

For higher security requirements, consider:
- Using `--touch-policy=cached` during setup (requires touch every 15 seconds)
- Running the proxy on-demand rather than as a persistent service
- Restricting proxy access via firewall rules or network namespaces

### Implementation notes

- Proxy binds to `localhost` only (not accessible from network)
- Temp files created with 0600 permissions and cleaned up after setup
- First available YubiKey is used (no multi-key selection currently)
- HTTP keep-alives are disabled by default - each request requires a new TLS handshake signed by the YubiKey, so removing the YubiKey immediately prevents further requests
- TLS 1.2 minimum enforced for upstream connections

## License

MIT
