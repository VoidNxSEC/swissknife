# NixOS Swissknife 🇨🇭

A portable suite of forensic and debug tools for NixOS, powered by Python, Rich, and ML.

## Tools

### 1. Swiss Rebuild (`swiss-rebuild`)
Real-time rebuild monitoring with forensic analysis.
- Visualizes build progress
- Detects failures instantly
- ML-powered error classification

### 2. Swiss Doctor (`swiss-doctor`)
Intelligent service diagnosis.
- Auto-detects failed units
- Analyzes logs and dependencies
- Suggets fixes

### 3. Swiss Monitor (`swiss-monitor`)
Real-time system & log anomaly detection.
- Streams journal logs
- Detects anomalies using ML
- Interactive dashboard

## Usage

Run directly from anywhere:

```bash
# Diagnose services
nix run path:/etc/nixos/projects/swissknife#swiss-doctor

# Monitor a rebuild
nix run path:/etc/nixos/projects/swissknife#swiss-rebuild

# Real-time monitor
nix run path:/etc/nixos/projects/swissknife#swiss-monitor
```

## Development

Enter the dev shell:
```bash
nix develop path:/etc/nixos/projects/swissknife
```
