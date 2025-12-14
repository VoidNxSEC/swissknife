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
          pygobject3
          psutil
          requests
          aiohttp
          rich
          dbus-python
        ]);

        # GTK4 application wrapper using proper NixOS method
        swiss-monitor = pkgs.stdenv.mkDerivation {
          pname = "swiss-monitor";
          version = "1.0.0";
          src = ./src;

          nativeBuildInputs = with pkgs; [
            wrapGAppsHook4
            gobject-introspection
          ];

          buildInputs = with pkgs; [
            gtk4
            libadwaita
            glib
            pango
            cairo
            gdk-pixbuf
            graphene
            harfbuzz
            pythonEnv
          ];

          dontBuild = true;

          installPhase = ''
            mkdir -p $out/bin $out/share/swiss-monitor
            cp ml_monitor.py $out/share/swiss-monitor/
            
            cat > $out/bin/swiss-monitor << EOF
            #!${pkgs.bash}/bin/bash
            exec ${pythonEnv}/bin/python $out/share/swiss-monitor/ml_monitor.py "\$@"
            EOF
            chmod +x $out/bin/swiss-monitor
          '';

          meta = with pkgs.lib; {
            description = "Professional SOC Monitor with GTK4/Adwaita";
            license = licenses.mit;
          };
        };

        # Systray wrapper
        swiss-systray = pkgs.stdenv.mkDerivation {
          pname = "swiss-systray";
          version = "1.0.0";
          src = ./src;

          nativeBuildInputs = with pkgs; [
            wrapGAppsHook4
            gobject-introspection
          ];

          buildInputs = with pkgs; [
            gtk4
            libadwaita
            glib
            libappindicator-gtk3
            pythonEnv
          ];

          dontBuild = true;

          installPhase = ''
            mkdir -p $out/bin $out/share/swiss-systray
            cp systray.py $out/share/swiss-systray/
            
            cat > $out/bin/swiss-systray << EOF
            #!${pkgs.bash}/bin/bash
            exec ${pythonEnv}/bin/python $out/share/swiss-systray/systray.py "\$@"
            EOF
            chmod +x $out/bin/swiss-systray
          '';
        };

        # Terminal-based tools (simpler, no GTK deps)
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
          inherit swiss-monitor swiss-systray;
          swiss-rebuild = mkTerminalTool "swiss-rebuild" ./src/rebuild_forensics.py;
          swiss-doctor = mkTerminalTool "swiss-doctor" ./src/service_doctor.py;
          default = swiss-monitor;
        };

        apps = {
          swiss-monitor = flake-utils.lib.mkApp { drv = swiss-monitor; };
          swiss-systray = flake-utils.lib.mkApp { drv = swiss-systray; };
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
            pkgs.gtk4
            pkgs.libadwaita
            pkgs.gobject-introspection
          ];

          shellHook = ''
            echo "🇨🇭 Swissknife Development Environment (GTK4)"
            echo ""
            echo "Commands:"
            echo "  python src/ml_monitor.py    - Run GTK4 SOC Monitor"
            echo "  python src/systray.py       - Run Systray (Wayland)"
            echo ""
          '';
        };
      }
    );
}
