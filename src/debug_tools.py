#!/usr/bin/env python3
"""
Swiss Debug Tools - Advanced debugging orchestration

Provides high-level interfaces to complex debugging tools:
- BPFTrace: eBPF-based syscall and kernel tracing
- Strace: System call tracing with smart filtering
- Perf: Performance profiling and flame graphs
- Tcpdump/Tshark: Network packet capture and analysis
- Valgrind/Heaptrack: Memory profiling
"""

import asyncio
import json
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Callable, Dict, Any
import threading


@dataclass
class TraceEvent:
    """Represents a traced event"""
    timestamp: str
    tool: str  # bpftrace, strace, perf, tcpdump
    pid: int
    event_type: str
    data: Dict[str, Any]
    severity: str = "info"  # info, warning, critical


class BPFTracer:
    """BPFTrace integration for eBPF-based tracing"""

    def __init__(self, on_event: Callable[[TraceEvent], None]):
        self.on_event = on_event
        self.process = None
        self.running = False

    def trace_process_syscalls(self, pid: int, syscalls: List[str] = None):
        """
        Trace specific syscalls for a process

        Args:
            pid: Process ID to trace
            syscalls: List of syscalls to monitor (default: network + file I/O)
        """
        if syscalls is None:
            syscalls = ['connect', 'accept', 'sendto', 'recvfrom', 'open', 'openat', 'write', 'read']

        # Build BPFTrace program
        program = f"""
tracepoint:syscalls:sys_enter_* /pid == {pid}/ {{
    @syscalls[probe] = count();
    printf("%s: PID=%d COMM=%s\\n", probe, pid, comm);
}}

interval:s:5 {{
    print(@syscalls);
    clear(@syscalls);
}}
"""
        self._run_bpftrace(program, pid)

    def trace_network_anomalies(self, pid: int):
        """Detect unusual network behavior"""
        program = f"""
#include <net/sock.h>

tracepoint:syscalls:sys_enter_connect /pid == {pid}/ {{
    $sockaddr = (struct sockaddr *)args->uservaddr;
    printf("CONNECT: PID=%d IP=%d\\n", pid, $sockaddr->sa_data);
}}

tracepoint:syscalls:sys_enter_sendto /pid == {pid} && args->len > 10000/ {{
    printf("LARGE_SEND: PID=%d SIZE=%d\\n", pid, args->len);
}}
"""
        self._run_bpftrace(program, pid)

    def trace_memory_anomalies(self, pid: int):
        """Detect memory allocation anomalies"""
        program = f"""
tracepoint:syscalls:sys_enter_mmap /pid == {pid} && args->len > 100*1024*1024/ {{
    printf("LARGE_ALLOC: PID=%d SIZE=%d\\n", pid, args->len);
}}

tracepoint:syscalls:sys_enter_brk /pid == {pid}/ {{
    @brk_calls = count();
}}

interval:s:1 {{
    if (@brk_calls > 1000) {{
        printf("EXCESSIVE_BRK: COUNT=%d\\n", @brk_calls);
    }}
    clear(@brk_calls);
}}
"""
        self._run_bpftrace(program, pid)

    def _run_bpftrace(self, program: str, pid: int):
        """Execute BPFTrace program"""
        self.running = True

        # Write program to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.bt', delete=False) as f:
            f.write(program)
            program_file = f.name

        try:
            self.process = subprocess.Popen(
                ['bpftrace', program_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            # Read output in thread
            threading.Thread(
                target=self._read_output,
                args=(pid,),
                daemon=True
            ).start()

        except Exception as e:
            print(f"BPFTrace error: {e}")
        finally:
            Path(program_file).unlink(missing_ok=True)

    def _read_output(self, pid: int):
        """Read and parse BPFTrace output"""
        if not self.process:
            return

        for line in self.process.stdout:
            try:
                if "CONNECT:" in line or "LARGE_SEND:" in line or "LARGE_ALLOC:" in line:
                    severity = "warning"
                elif "EXCESSIVE_BRK:" in line:
                    severity = "critical"
                else:
                    severity = "info"

                event = TraceEvent(
                    timestamp=datetime.now().isoformat(),
                    tool="bpftrace",
                    pid=pid,
                    event_type=line.split(":")[0] if ":" in line else "trace",
                    data={"raw": line.strip()},
                    severity=severity
                )
                self.on_event(event)

            except Exception:
                continue

    def stop(self):
        """Stop tracing"""
        self.running = False
        if self.process:
            self.process.terminate()
            self.process.wait()


class StraceAnalyzer:
    """Advanced strace integration with intelligent filtering"""

    def __init__(self, on_event: Callable[[TraceEvent], None]):
        self.on_event = on_event
        self.process = None

    def trace_suspicious_behavior(self, pid: int):
        """
        Trace syscalls that might indicate malicious behavior:
        - Network connections
        - File operations in sensitive directories
        - Process spawning
        - Memory manipulation
        """
        syscalls = [
            'connect', 'bind', 'listen', 'accept',  # Network
            'execve', 'fork', 'clone',              # Process spawning
            'ptrace',                                # Debugging/injection
            'open', 'openat', 'write', 'unlink',    # File ops
            'mmap', 'mprotect'                       # Memory ops
        ]

        cmd = [
            'strace',
            '-f',  # Follow forks
            '-p', str(pid),
            '-e', 'trace=' + ','.join(syscalls),
            '-tt',  # Timestamps
            '-T',   # Time spent in syscall
            '-y',   # Print paths
        ]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            threading.Thread(
                target=self._parse_strace,
                args=(pid,),
                daemon=True
            ).start()

        except Exception as e:
            print(f"Strace error: {e}")

    def _parse_strace(self, pid: int):
        """Parse strace output and detect anomalies"""
        if not self.process:
            return

        suspicious_patterns = {
            '/etc/shadow': 'critical',
            '/etc/passwd': 'critical',
            '/root/': 'warning',
            'execve': 'warning',
            'ptrace': 'critical',
        }

        for line in self.process.stderr:  # strace outputs to stderr
            try:
                severity = "info"
                event_type = "syscall"

                # Check for suspicious patterns
                for pattern, sev in suspicious_patterns.items():
                    if pattern in line:
                        severity = sev
                        event_type = f"suspicious_{pattern.replace('/', '_')}"
                        break

                # Parse syscall name
                if '(' in line:
                    syscall = line.split('(')[0].split()[-1]
                else:
                    syscall = "unknown"

                event = TraceEvent(
                    timestamp=datetime.now().isoformat(),
                    tool="strace",
                    pid=pid,
                    event_type=event_type,
                    data={"syscall": syscall, "raw": line.strip()},
                    severity=severity
                )

                if severity in ("warning", "critical"):
                    self.on_event(event)

            except Exception:
                continue

    def stop(self):
        """Stop tracing"""
        if self.process:
            self.process.terminate()
            self.process.wait()


class PerfProfiler:
    """Performance profiling with perf"""

    def __init__(self, on_event: Callable[[TraceEvent], None]):
        self.on_event = on_event

    def profile_cpu_hotspots(self, pid: int, duration: int = 10):
        """
        Profile CPU usage and identify hotspots

        Args:
            pid: Process to profile
            duration: Profiling duration in seconds
        """
        output_file = f"/tmp/perf_{pid}_{datetime.now().timestamp()}.data"

        cmd = [
            'perf', 'record',
            '-p', str(pid),
            '-g',  # Call graph
            '-F', '99',  # 99 Hz sampling
            '-o', output_file,
            '--', 'sleep', str(duration)
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True)

            # Generate report
            report = subprocess.run(
                ['perf', 'report', '-i', output_file, '--stdio'],
                capture_output=True,
                text=True
            )

            event = TraceEvent(
                timestamp=datetime.now().isoformat(),
                tool="perf",
                pid=pid,
                event_type="cpu_profile",
                data={
                    "duration": duration,
                    "report": report.stdout[:1000],  # First 1000 chars
                    "data_file": output_file
                },
                severity="info"
            )
            self.on_event(event)

        except Exception as e:
            print(f"Perf error: {e}")


class NetworkCapture:
    """Network packet capture with tcpdump/tshark"""

    def __init__(self, on_event: Callable[[TraceEvent], None]):
        self.on_event = on_event
        self.process = None

    def capture_process_traffic(self, pid: int, interface: str = "any"):
        """Capture network traffic for a specific process"""

        # Get connections for this PID to filter
        try:
            import psutil
            proc = psutil.Process(pid)
            connections = proc.connections(kind='inet')

            if not connections:
                return

            # Build BPF filter for this process's connections
            filters = []
            for conn in connections:
                if conn.laddr:
                    filters.append(f"port {conn.laddr.port}")

            bpf_filter = " or ".join(filters[:10])  # Limit to avoid too long filter

        except Exception:
            bpf_filter = ""

        # Use tshark for better parsing
        cmd = [
            'tshark',
            '-i', interface,
            '-f', bpf_filter,
            '-T', 'json',
            '-e', 'frame.time',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'frame.len',
        ]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            threading.Thread(
                target=self._parse_packets,
                args=(pid,),
                daemon=True
            ).start()

        except Exception as e:
            print(f"Network capture error: {e}")

    def _parse_packets(self, pid: int):
        """Parse captured packets"""
        if not self.process:
            return

        buffer = ""
        for line in self.process.stdout:
            buffer += line

            # Try to parse complete JSON
            try:
                packets = json.loads(buffer)
                for packet in packets:
                    event = TraceEvent(
                        timestamp=datetime.now().isoformat(),
                        tool="tshark",
                        pid=pid,
                        event_type="packet",
                        data=packet,
                        severity="info"
                    )
                    self.on_event(event)
                buffer = ""
            except json.JSONDecodeError:
                continue

    def stop(self):
        """Stop capture"""
        if self.process:
            self.process.terminate()
            self.process.wait()


class MemoryProfiler:
    """Memory profiling with heaptrack"""

    def __init__(self, on_event: Callable[[TraceEvent], None]):
        self.on_event = on_event

    def profile_memory_leaks(self, pid: int, duration: int = 30):
        """
        Attach heaptrack to running process and detect leaks

        Args:
            pid: Process to profile
            duration: Profiling duration
        """
        output_file = f"/tmp/heaptrack_{pid}_{datetime.now().timestamp()}.gz"

        cmd = [
            'heaptrack',
            '-p', str(pid),
            '-o', output_file
        ]

        try:
            process = subprocess.Popen(cmd)

            # Let it run for specified duration
            threading.Timer(
                duration,
                lambda: self._stop_and_analyze(process, output_file, pid)
            ).start()

        except Exception as e:
            print(f"Heaptrack error: {e}")

    def _stop_and_analyze(self, process, output_file: str, pid: int):
        """Stop profiling and analyze results"""
        process.terminate()
        process.wait()

        # Analyze with heaptrack_print
        try:
            result = subprocess.run(
                ['heaptrack_print', output_file],
                capture_output=True,
                text=True,
                timeout=30
            )

            event = TraceEvent(
                timestamp=datetime.now().isoformat(),
                tool="heaptrack",
                pid=pid,
                event_type="memory_profile",
                data={
                    "summary": result.stdout[:1000],
                    "data_file": output_file
                },
                severity="info"
            )
            self.on_event(event)

        except Exception as e:
            print(f"Heaptrack analysis error: {e}")
