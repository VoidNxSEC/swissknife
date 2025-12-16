# 🇨🇭 Swiss Monitor SOC - Professional Security Operations Center

**Advanced SOC toolkit with intelligent auto-forensics and real-time debugging**

## Features

### 🔬 Auto-Forensics Engine
Intelligent anomaly detection that automatically triggers appropriate debugging tools:

- **High CPU Usage** → Perf profiling with flame graphs
- **Memory Leaks** → Heaptrack analysis + BPFTrace memory syscalls
- **Suspicious Network** → Packet capture (Wireshark/tshark) + BPFTrace network tracing
- **Crypto Mining Detection** → Full forensics: strace + perf + network analysis
- **File System Abuse** → Strace with intelligent filtering
- **Process Injection** → Ptrace detection

### 🛡️ Security Monitoring
- Real-time journald log streaming with severity filtering
- Suricata IDS integration
- Behavioral anomaly detection using baselines
- Suspicious port detection (backdoor ports: 4444, 5555, 6666, 31337)

### 🎨 Professional UI
- GTK4/Adwaita native interface
- Glassmorphism design with dark mode
- Live forensics dashboard
- Real-time system vitals
- Color-coded severity levels

### 🔧 Debug Tools Integration
- **BPFTrace**: eBPF-based syscall and kernel tracing
- **Strace**: System call tracing with smart filtering
- **Perf**: CPU profiling and performance analysis
- **Heaptrack**: Memory leak detection
- **Wireshark/Tshark**: Network packet analysis
- **Nethogs/Iftop**: Network bandwidth monitoring
- **Valgrind**: Memory debugging

## Installation

### NixOS (via Flake)

Add to your `/etc/nixos/flake.nix`:

```nix
{
  inputs = {
    swissknife.url = "path:/home/kernelcore/dev/projects/swissknife";
  };

  outputs = { nixpkgs, swissknife, ... }: {
    nixosConfigurations.yourhost = nixpkgs.lib.nixosSystem {
      modules = [{
        environment.systemPackages = [
          swissknife.packages.x86_64-linux.swiss-monitor
          swissknife.packages.x86_64-linux.swiss-debug-tools
          swissknife.packages.x86_64-linux.swiss-systray
        ];
      }];
    };
  };
}
```

Then rebuild:
```bash
sudo nixos-rebuild switch --flake /etc/nixos#kernelcore --max-jobs 8 --cores 8
```

### Development

```bash
nix develop
python src/ml_monitor_v2.py  # Run v2 with auto-forensics
```

## Usage

### Swiss Monitor v2 (Recommended)
```bash
swiss-monitor-v2
```

Features:
- Auto-forensics engine enabled
- Real-time anomaly detection
- Automatic debugging tool orchestration
- Live forensics dashboard

### Swiss Monitor v1 (Classic)
```bash
swiss-monitor
```

Original version without auto-forensics.

### System Tray
```bash
swiss-systray
```

Systray indicator that:
- Shows red icon on critical alerts
- Monitors journald for security events
- Quick access to SOC monitor
- Desktop notifications

### Context Process Monitor
```bash
swiss-btop [process_name]
# Example:
swiss-btop brave
```

Monitor specific processes with:
- CPU/Memory usage
- Active network connections
- Live journald logs filtered by process

## Auto-Forensics Engine

### How It Works

1. **Baseline Learning**: The engine learns normal behavior for each process
2. **Anomaly Detection**: Detects deviations from baseline using multiple heuristics
3. **Intelligent Response**: Automatically triggers appropriate debug tools
4. **Data Collection**: Collects forensics data for analysis
5. **Dashboard Display**: Shows real-time forensics events in the UI

### Detected Anomalies

| Anomaly Type | Trigger Condition | Auto-Forensics Action |
|-------------|-------------------|----------------------|
| High CPU | CPU > 80% | Perf profiling (10s) |
| High Memory | Memory > 500MB | Heaptrack analysis |
| Memory Leak | Growth > 50MB/min | Heaptrack + BPFTrace memory syscalls |
| Suspicious Network | Connections to ports 4444, 5555, 6666, 31337 | Packet capture + BPFTrace |
| Rapid Connections | >50 active connections | Network monitoring |
| Crypto Mining | High CPU + known miner names | Full forensics: strace + perf + network |

### Example Workflow

1. User runs `swiss-monitor-v2`
2. Auto-forensics engine starts monitoring all processes
3. Detects anomaly: Process "suspicious" using 95% CPU
4. Automatically triggers:
   - Perf profiling for 10 seconds
   - Collects flame graph data
5. Results appear in Forensics Dashboard
6. User can investigate further with raw perf data

## Debug Tools Package

The `swiss-debug-tools` package includes:

### Debuggers
- gdb - GNU Debugger
- lldb - LLVM Debugger

### Tracers
- strace - System call tracer
- ltrace - Library call tracer
- bpftrace - eBPF tracing language

### Memory Profilers
- valgrind - Memory debugger
- heaptrack - Heap memory profiler

### Performance Tools
- perf - Kernel performance tools
- hotspot - GUI for perf data visualization
- sysstat - System performance (sar, iostat, mpstat)

### Process Monitors
- iotop - I/O monitor
- nethogs - Network bandwidth per process
- iftop - Network bandwidth monitor
- nmon - Performance monitor
- atop - Advanced system monitor
- lsof - List open files

### Network Analysis
- tcpdump - Packet analyzer (CLI)
- wireshark - Protocol analyzer (GUI)
- tshark - Protocol analyzer (CLI)

## Architecture

```
┌─────────────────────────────────────────────┐
│         Swiss Monitor GTK4 UI               │
│  (ml_monitor_v2.py)                         │
│  - Forensics Dashboard                      │
│  - Security Logs                            │
│  - System Vitals                            │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│      Auto-Forensics Engine                  │
│  (auto_forensics.py)                        │
│  - Anomaly Detection                        │
│  - Baseline Learning                        │
│  - Tool Orchestration                       │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│        Debug Tools Layer                    │
│  (debug_tools.py)                           │
│  - BPFTracer                                │
│  - StraceAnalyzer                           │
│  - PerfProfiler                             │
│  - NetworkCapture                           │
│  - MemoryProfiler                           │
└─────────────────────────────────────────────┘
```

## Configuration

### Anomaly Detection Thresholds

Edit `auto_forensics.py`:

```python
class AnomalyDetector:
    CPU_THRESHOLD = 80.0  # %
    MEMORY_THRESHOLD = 500  # MB
    MEMORY_GROWTH_RATE = 50  # MB/min
    CONNECTION_RATE_THRESHOLD = 10  # connections/sec
```

### Forensics Auto-Cleanup

Forensics sessions are automatically cleaned up after 5 minutes to prevent resource exhaustion.

## Requirements

- NixOS (or Nix package manager)
- Root privileges for some debug tools (BPFTrace, packet capture)
- Suricata IDS (optional, for IDS integration)
- Ollama (optional, for AI chat features)

## Tips

### Running with Elevated Privileges

Some debug tools require root:

```bash
sudo swiss-monitor-v2
```

### View Raw Forensics Data

Perf data: `/tmp/perf_<pid>_<timestamp>.data`
```bash
perf report -i /tmp/perf_12345_*.data
hotspot /tmp/perf_12345_*.data  # GUI visualization
```

Heaptrack data: `/tmp/heaptrack_<pid>_<timestamp>.gz`
```bash
heaptrack_print /tmp/heaptrack_12345_*.gz
```

### Integration with Hyprland/Waybar

The systray uses StatusNotifierItem protocol and works with:
- Waybar
- Hyprland
- Any Wayland compositor with SNI support

## Original Tools

### Swiss Rebuild (`swiss-rebuild`)
Real-time rebuild monitoring with forensic analysis.
- Visualizes build progress
- Detects failures instantly
- ML-powered error classification

### Swiss Doctor (`swiss-doctor`)
Intelligent service diagnosis.
- Auto-detects failed units
- Analyzes logs and dependencies
- Suggests fixes

## Contributing

This is a professional SOC toolkit. Contributions welcome for:
- New anomaly detection heuristics
- Additional debug tool integrations
- UI/UX improvements
- Performance optimizations

## License

MIT License

## Author

VoidNxSec - Professional Security Operations Center Toolkit

---

**🇨🇭 Swiss precision for security monitoring**
