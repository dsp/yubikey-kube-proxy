{ pkgs, lib, config, inputs, ... }:

{
  # https://devenv.sh/packages/
  # pcsclite is Linux-only; macOS provides the PCSC system framework that
  # piv-go links against. Pulling pcsclite in on macOS injects its headers
  # into the compiler search path and breaks the cgo build.
  packages = [ pkgs.git pkgs.kubectl pkgs.kubectl-ai pkgs.pkg-config pkgs.yubikey-manager pkgs.yq ]
    ++ lib.optionals pkgs.stdenv.isLinux [ pkgs.pcsclite ];

  # https://devenv.sh/languages/
  languages.go.enable = true;
}
