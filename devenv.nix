{ pkgs, lib, config, inputs, ... }:

{
  # https://devenv.sh/packages/
  packages = [ pkgs.git pkgs.kubectl pkgs.kubectl-ai pkgs.pcsclite pkgs.pkg-config pkgs.yubikey-manager pkgs.yq ];

  # https://devenv.sh/languages/
  languages.go.enable = true;
}
