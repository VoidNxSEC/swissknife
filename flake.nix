{
  description = "NixOS Swissknife - Portable Debug & Forensic Tools";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        
        # Python environment with dependencies
        pythonEnv = pkgs.python313.withPackages (ps: with ps; [
          rich
          requests
          psutil
          dbus-python
          systemd-python
        ]);

        # Core script builder
        mkTool = name: src: pkgs.writeScriptBin name ''
          #!${pythonEnv}/bin/python
          import sys
          import os
          sys.path.append("${./src}")
          
          # Execute the source file
          with open("${src}") as f:
              exec(f.read())
        '';

      in
      {
        packages = {
          swiss-rebuild = mkTool "swiss-rebuild" ./src/rebuild_forensics.py;
          swiss-doctor = mkTool "swiss-doctor" ./src/service_doctor.py;
          swiss-monitor = mkTool "swiss-monitor" ./src/ml_monitor.py;
          default = self.packages.${system}.swiss-doctor;
        };

        apps = {
          swiss-rebuild = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-rebuild; };
          swiss-doctor = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-doctor; };
          swiss-monitor = flake-utils.lib.mkApp { drv = self.packages.${system}.swiss-monitor; };
          default = self.apps.${system}.swiss-doctor;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pythonEnv
            pkgs.black
            pkgs.mypy
            pkgs.ruff
          ];
        };
      }
    );
}
