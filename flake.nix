{
  description = "A proxy for Kubernetes authentication using YubiKey";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        yubikey-kube-proxy = pkgs.buildGoModule {
          pname = "yubikey-kube-proxy";
          version = "0.1.0";

          src = ./.;

          vendorHash = "sha256-O0W90fLo7Sgzose6UwMVCIcHIcqUQ+xxvZAB7uqtqGQ=";

          nativeBuildInputs = [ pkgs.pkg-config pkgs.makeWrapper ];

          buildInputs = [ pkgs.pcsclite ];

          # Ensure pcsclite is available at runtime
          postInstall = ''
            wrapProgram $out/bin/yubikey-kube-proxy \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.yubikey-manager ]}
          '';

          nativeCheckInputs = [ pkgs.pcsclite ];

          meta = with pkgs.lib; {
            description = "A proxy for Kubernetes authentication using YubiKey";
            homepage = "https://github.com/dsp/yubikey-kube-proxy";
            license = licenses.mit;
            maintainers = [ ];
            platforms = platforms.linux ++ platforms.darwin;
          };
        };
      in
      {
        packages = {
          default = yubikey-kube-proxy;
          yubikey-kube-proxy = yubikey-kube-proxy;
        };

        apps.default = flake-utils.lib.mkApp {
          drv = yubikey-kube-proxy;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go
            pkgs.pkg-config
            pkgs.pcsclite
            pkgs.yubikey-manager
            pkgs.kubectl
          ];
        };
      }
    ) // {
      # Overlay for easy integration into NixOS configurations
      overlays.default = final: prev: {
        yubikey-kube-proxy = self.packages.${prev.system}.yubikey-kube-proxy;
      };

      # NixOS module for system-wide installation
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.programs.yubikey-kube-proxy;
        in
        {
          options.programs.yubikey-kube-proxy = {
            enable = lib.mkEnableOption "yubikey-kube-proxy";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.yubikey-kube-proxy;
              description = "The yubikey-kube-proxy package to use";
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];

            # Ensure pcscd service is enabled for YubiKey access
            services.pcscd.enable = true;
          };
        };
    };
}
