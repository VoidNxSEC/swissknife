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

            # Copy all Python modules
            cp ml_monitor.py $out/share/swiss-monitor/
            cp ml_monitor_v2.py $out/share/swiss-monitor/
            cp debug_tools.py $out/share/swiss-monitor/
            cp auto_forensics.py $out/share/swiss-monitor/

            # Copy CSS styling
            cp style.css $out/share/swiss-monitor/

            # Create v1 wrapper (original)
            cat > $out/bin/swiss-monitor << EOF
            #!${pkgs.bash}/bin/bash
            export PYTHONPATH=$out/share/swiss-monitor:\$PYTHONPATH
            exec ${pythonEnv}/bin/python $out/share/swiss-monitor/ml_monitor.py "\$@"
            EOF
            chmod +x $out/bin/swiss-monitor

            # Create v2 wrapper (with auto-forensics)
            cat > $out/bin/swiss-monitor-v2 << EOF
            #!${pkgs.bash}/bin/bash
            export PYTHONPATH=$out/share/swiss-monitor:\$PYTHONPATH
            exec ${pythonEnv}/bin/python $out/share/swiss-monitor/ml_monitor_v2.py "\$@"
            EOF
            chmod +x $out/bin/swiss-monitor-v2
          '';

          meta = with pkgs.lib; {
            description = "Professional SOC Monitor with Auto-Forensics Engine";
            longDescription = ''
              Swiss Monitor - Advanced Security Operations Center with:
              - GTK4/Adwaita native UI with glassmorphism design
              - Auto-Forensics engine with intelligent anomaly detection
              - Real-time debugging integration (BPFTrace, Strace, Perf, Wireshark)
              - Live forensics dashboard
              - Journald and Suricata IDS monitoring
              - AI-powered threat analysis (Ollama)

              Commands:
                swiss-monitor    - Launch v1 (original)
                swiss-monitor-v2 - Launch v2 (with auto-forensics)
            '';
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

        # Debug and profiling tools package for SOC investigations
        swiss-debug-tools = pkgs.buildEnv {
          name = "swiss-debug-tools";
          paths = with pkgs; [
            # Debuggers
            gdb                    # GNU Debugger
            lldb                   # LLVM Debugger

            # System call & library tracers
            strace                 # System call tracer
            ltrace                 # Library call tracer

            # Memory profilers
            valgrind               # Memory debugger and profiler
            heaptrack              # Heap memory profiler

            # Performance analysis
            linuxPackages.perf     # Kernel perf tools
            hotspot                # GUI for perf data
            sysstat                # sar, iostat, mpstat
            bpftrace               # eBPF tracing language

            # Process & resource monitors
            iotop                  # I/O monitor
            nethogs                # Network bandwidth per process
            iftop                  # Network bandwidth monitor
            nmon                   # Performance monitor
            atop                   # Advanced system monitor
            lsof                   # List open files

            # Network analysis
            tcpdump                # Packet analyzer (CLI)
            #wireshark              # Protocol analyzer (GUI)
            tshark                 # Protocol analyzer (CLI)
          ];
          pathsToLink = [ "/bin" "/share" ];

          meta = with pkgs.lib; {
            description = "Comprehensive debugging and profiling toolkit for SOC investigations";
            longDescription = ''
              Collection of debugging, tracing, profiling, and analysis tools
              for deep forensic investigation when Swiss Monitor SOC detects anomalies.

              Includes system debuggers (gdb, lldb), tracers (strace, ltrace, bpftrace),
              memory profilers (valgrind, heaptrack), performance tools (perf, hotspot),
              and network analyzers (wireshark, tcpdump, nethogs).
            '';
            license = licenses.mit;
          };
        };

      in
      {
        packages = {
          inherit swiss-monitor swiss-systray swiss-debug-tools;
          swiss-rebuild = mkTerminalTool "swiss-rebuild" ./src/rebuild_forensics.py;
          swiss-doctor = mkTerminalTool "swiss-doctor" ./src/service_doctor.py;
          swiss-btop = mkTerminalTool "swiss-btop" ./src/swiss_btop.py;
          default = swiss-monitor;
        };

        apps = {
          swiss-monitor = flake-utils.lib.mkApp { drv = swiss-monitor; };
          swiss-systray = flake-utils.lib.mkApp { drv = swiss-systray; };
          swiss-rebuild = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-rebuild; };
          swiss-doctor = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-doctor; };
          swiss-btop = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-btop; };
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

            # Debug and profiling tools (available in dev environment)
            swiss-debug-tools
          ];

          shellHook = ''
            echo "🇨🇭 Swissknife Development Environment (GTK4)"
            echo ""
            echo "Commands:"
            echo "  python src/ml_monitor.py    - Run GTK4 SOC Monitor"
            echo "  python src/systray.py       - Run Systray (Wayland)"
            echo "  python src/swiss_btop.py    - Run Context Process Monitor"
            echo ""
            echo "Debug Tools Available:"
            echo "  gdb, lldb, strace, ltrace, valgrind, heaptrack"
            echo "  perf, hotspot, bpftrace, iotop, nethogs, iftop"
            echo "  nmon, atop, lsof, tcpdump, wireshark, tshark"
            echo ""
          '';
        };
      }
    );
}
