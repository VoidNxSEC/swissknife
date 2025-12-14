{
  description = "NixOS Swissknife - Professional SOC Monitor & Debug Tools";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Python environment with all dependencies for TUI SOC
        pythonEnv = pkgs.python313.withPackages (ps: with ps; [
          # Core TUI
          textual
          rich

          # Async & Network
          aiohttp
          requests

          # System monitoring
          psutil
          dbus-python
          systemd-python

          # Optional: ML/AI
          # ollama  # Use API instead
        ]);

        # GTK4 environment for systray
        gtkEnv = with pkgs; [
          gtk4
          libappindicator-gtk3
          gobject-introspection
        ];

        # Core tool builder with proper shebang
        mkTool = name: src: pkgs.writeScriptBin name ''
          #!${pythonEnv}/bin/python
          import sys
          sys.path.insert(0, "${./src}")

          # Execute the source file
          with open("${src}") as f:
              exec(compile(f.read(), "${src}", "exec"))
        '';

        # Systray indicator script
        systrayScript = pkgs.writeScriptBin "swiss-systray" ''
          #!${pkgs.python313.withPackages (ps: with ps; [ pygobject3 ])}/bin/python
          ${builtins.readFile ./src/systray.py}
        '';

      in
      {
        packages = {
          swiss-rebuild = mkTool "swiss-rebuild" ./src/rebuild_forensics.py;
          swiss-doctor = mkTool "swiss-doctor" ./src/service_doctor.py;
          swiss-monitor = mkTool "swiss-monitor" ./src/ml_monitor.py;
          swiss-systray = systrayScript;
          default = self.packages.${system}.swiss-monitor;
        };

        apps = {
          swiss-rebuild = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-rebuild; };
          swiss-doctor = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-doctor; };
          swiss-monitor = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-monitor; };
          swiss-systray = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-systray; };
          default = self.apps.${system}.swiss-monitor;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pythonEnv
            pkgs.black
            pkgs.mypy
            pkgs.ruff
          ] ++ gtkEnv;

          shellHook = ''
            echo "🇨🇭 Swissknife Development Environment"
            echo ""
            echo "Commands:"
            echo "  python src/ml_monitor.py    - Run TUI SOC Monitor"
            echo "  python src/systray.py       - Run Systray (Wayland)"
            echo "  python src/service_doctor.py - Run System Doctor"
            echo ""
          '';
        };
      }
    );
}
