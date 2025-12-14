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

        # Python environment with GTK4/Adwaita for GUI
        pythonEnv = pkgs.python313.withPackages (ps: with ps; [
          # GTK4
          pygobject3

          # System monitoring
          psutil

          # Network/API
          requests
          aiohttp

          # Core
          rich
          dbus-python
        ]);

        # GTK4/Adwaita runtime dependencies
        gtkDeps = with pkgs; [
          gtk4
          libadwaita
          gobject-introspection
          gsettings-desktop-schemas
          hicolor-icon-theme
          adwaita-icon-theme
        ];

        # Wrapper for GTK4 applications
        wrapGtkApp = name: script: pkgs.writeShellScriptBin name ''
          export GI_TYPELIB_PATH="${pkgs.lib.makeSearchPath "lib/girepository-1.0" gtkDeps}"
          export XDG_DATA_DIRS="${pkgs.lib.makeSearchPath "share" gtkDeps}:$XDG_DATA_DIRS"
          export GDK_BACKEND=wayland,x11
          exec ${pythonEnv}/bin/python ${script} "$@"
        '';

        # Terminal-based tools
        mkTerminalTool = name: src: pkgs.writeScriptBin name ''
          #!${pythonEnv}/bin/python
          import sys
          sys.path.insert(0, "${./src}")
          with open("${src}") as f:
              exec(compile(f.read(), "${src}", "exec"))
        '';

      in
      {
        packages = {
          # GTK4 GUI applications
          swiss-monitor = wrapGtkApp "swiss-monitor" ./src/ml_monitor.py;
          swiss-systray = wrapGtkApp "swiss-systray" ./src/systray.py;

          # Terminal tools
          swiss-rebuild = mkTerminalTool "swiss-rebuild" ./src/rebuild_forensics.py;
          swiss-doctor = mkTerminalTool "swiss-doctor" ./src/service_doctor.py;

          default = self.packages.${system}.swiss-monitor;
        };

        apps = {
          swiss-monitor = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-monitor; };
          swiss-systray = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-systray; };
          swiss-rebuild = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-rebuild; };
          swiss-doctor = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-doctor; };
          default = self.apps.${system}.swiss-monitor;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pythonEnv
            pkgs.black
            pkgs.mypy
            pkgs.ruff
          ] ++ gtkDeps;

          shellHook = ''
            export GI_TYPELIB_PATH="${pkgs.lib.makeSearchPath "lib/girepository-1.0" gtkDeps}"
            export XDG_DATA_DIRS="${pkgs.lib.makeSearchPath "share" gtkDeps}:$XDG_DATA_DIRS"
            export GDK_BACKEND=wayland,x11

            echo "🇨🇭 Swissknife Development Environment (GTK4)"
            echo ""
            echo "Commands:"
            echo "  python src/ml_monitor.py    - Run GTK4 SOC Monitor"
            echo "  python src/systray.py       - Run Systray (Wayland)"
            echo "  python src/service_doctor.py - Run System Doctor"
            echo ""
          '';
        };
      }
    );
}
