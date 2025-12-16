#!/usr/bin/env python3
"""
Auto Forensics Engine - Intelligent debugging orchestration

Automatically triggers appropriate debugging tools based on anomaly detection:
- High CPU → perf profiling
- High memory → heaptrack analysis
- Suspicious network → packet capture + bpftrace
- File system anomalies → strace monitoring
- Process injection → ptrace detection
"""

import psutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Optional, Set
from enum import Enum

from debug_tools import (
    BPFTracer, StraceAnalyzer, PerfProfiler,
    NetworkCapture, MemoryProfiler, TraceEvent
)


class AnomalyType(Enum):
    """Types of detectable anomalies"""
    HIGH_CPU = "high_cpu"
    HIGH_MEMORY = "high_memory"
    MEMORY_LEAK = "memory_leak"
    SUSPICIOUS_NETWORK = "suspicious_network"
    RAPID_CONNECTIONS = "rapid_connections"
    FILE_SYSTEM_ABUSE = "file_system_abuse"
    PROCESS_INJECTION = "process_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CRYPTO_MINING = "crypto_mining"


@dataclass
class Anomaly:
    """Represents a detected anomaly"""
    type: AnomalyType
    pid: int
    process_name: str
    severity: str  # info, warning, critical
    timestamp: str
    metrics: Dict[str, any]
    description: str
    auto_forensics_triggered: bool = False
    forensics_data: List[TraceEvent] = field(default_factory=list)


@dataclass
class ProcessBaseline:
    """Baseline metrics for a process"""
    pid: int
    name: str
    avg_cpu: float = 0.0
    avg_memory: float = 0.0
    avg_connections: int = 0
    avg_io_ops: int = 0
    samples: int = 0
    first_seen: datetime = field(default_factory=datetime.now)


class AnomalyDetector:
    """Intelligent anomaly detection using behavioral analysis"""

    # Thresholds
    CPU_THRESHOLD = 80.0  # %
    MEMORY_THRESHOLD = 500  # MB
    MEMORY_GROWTH_RATE = 50  # MB/min
    CONNECTION_RATE_THRESHOLD = 10  # connections/sec
    IO_OPS_THRESHOLD = 10000  # ops/sec

    def __init__(self):
        self.baselines: Dict[int, ProcessBaseline] = {}
        self.anomalies: List[Anomaly] = []
        self.monitored_pids: Set[int] = set()

    def update_baseline(self, proc: psutil.Process):
        """Update baseline metrics for a process"""
        try:
            pid = proc.pid

            if pid not in self.baselines:
                self.baselines[pid] = ProcessBaseline(
                    pid=pid,
                    name=proc.name()
                )

            baseline = self.baselines[pid]

            # Get current metrics
            cpu = proc.cpu_percent(interval=0.1)
            memory = proc.memory_info().rss / 1024 / 1024  # MB

            try:
                connections = len(proc.connections(kind='inet'))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                connections = 0

            try:
                io = proc.io_counters()
                io_ops = io.read_count + io.write_count
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                io_ops = 0

            # Update running averages
            baseline.samples += 1
            alpha = 0.3  # Exponential smoothing factor

            baseline.avg_cpu = alpha * cpu + (1 - alpha) * baseline.avg_cpu
            baseline.avg_memory = alpha * memory + (1 - alpha) * baseline.avg_memory
            baseline.avg_connections = alpha * connections + (1 - alpha) * baseline.avg_connections
            baseline.avg_io_ops = alpha * io_ops + (1 - alpha) * baseline.avg_io_ops

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def detect_anomalies(self, proc: psutil.Process) -> List[Anomaly]:
        """Detect anomalies for a process"""
        anomalies = []

        try:
            pid = proc.pid
            name = proc.name()

            # Get current metrics
            cpu = proc.cpu_percent(interval=0.1)
            mem_info = proc.memory_info()
            memory_mb = mem_info.rss / 1024 / 1024

            # High CPU detection
            if cpu > self.CPU_THRESHOLD:
                anomalies.append(Anomaly(
                    type=AnomalyType.HIGH_CPU,
                    pid=pid,
                    process_name=name,
                    severity="warning",
                    timestamp=datetime.now().isoformat(),
                    metrics={"cpu": cpu},
                    description=f"Process using {cpu:.1f}% CPU"
                ))

            # High memory detection
            if memory_mb > self.MEMORY_THRESHOLD:
                anomalies.append(Anomaly(
                    type=AnomalyType.HIGH_MEMORY,
                    pid=pid,
                    process_name=name,
                    severity="warning",
                    timestamp=datetime.now().isoformat(),
                    metrics={"memory_mb": memory_mb},
                    description=f"Process using {memory_mb:.1f} MB"
                ))

            # Memory leak detection (if we have baseline)
            if pid in self.baselines:
                baseline = self.baselines[pid]
                if baseline.samples > 10:  # Need enough samples
                    memory_growth = memory_mb - baseline.avg_memory
                    if memory_growth > self.MEMORY_GROWTH_RATE:
                        anomalies.append(Anomaly(
                            type=AnomalyType.MEMORY_LEAK,
                            pid=pid,
                            process_name=name,
                            severity="critical",
                            timestamp=datetime.now().isoformat(),
                            metrics={
                                "current_mb": memory_mb,
                                "baseline_mb": baseline.avg_memory,
                                "growth_mb": memory_growth
                            },
                            description=f"Memory growing by {memory_growth:.1f} MB"
                        ))

            # Suspicious network activity
            try:
                connections = proc.connections(kind='inet')
                active_conns = [c for c in connections if c.status == 'ESTABLISHED']

                # Detect connections to unusual ports
                suspicious_ports = set()
                for conn in active_conns:
                    if conn.raddr and conn.raddr.port in [4444, 5555, 6666, 31337]:  # Common backdoor ports
                        suspicious_ports.add(conn.raddr.port)

                if suspicious_ports:
                    anomalies.append(Anomaly(
                        type=AnomalyType.SUSPICIOUS_NETWORK,
                        pid=pid,
                        process_name=name,
                        severity="critical",
                        timestamp=datetime.now().isoformat(),
                        metrics={"suspicious_ports": list(suspicious_ports)},
                        description=f"Connections to suspicious ports: {suspicious_ports}"
                    ))

                # Rapid connection detection
                if len(active_conns) > 50:
                    anomalies.append(Anomaly(
                        type=AnomalyType.RAPID_CONNECTIONS,
                        pid=pid,
                        process_name=name,
                        severity="warning",
                        timestamp=datetime.now().isoformat(),
                        metrics={"connection_count": len(active_conns)},
                        description=f"{len(active_conns)} active connections"
                    ))

            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Crypto mining detection heuristics
            if cpu > 90 and name.lower() in ['xmrig', 'minergate', 'cpuminer']:
                anomalies.append(Anomaly(
                    type=AnomalyType.CRYPTO_MINING,
                    pid=pid,
                    process_name=name,
                    severity="critical",
                    timestamp=datetime.now().isoformat(),
                    metrics={"cpu": cpu, "name": name},
                    description=f"Potential crypto miner detected: {name}"
                ))

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return anomalies


class AutoForensicsEngine:
    """
    Orchestrates debugging tools based on detected anomalies

    Workflow:
    1. Monitor processes for anomalies
    2. When anomaly detected, trigger appropriate debug tools
    3. Collect forensics data
    4. Present findings to user
    """

    def __init__(self, on_forensics_event: Callable[[TraceEvent], None]):
        self.detector = AnomalyDetector()
        self.on_forensics_event = on_forensics_event

        # Active debugging sessions
        self.active_tracers: Dict[int, List] = {}  # pid -> [tracer objects]
        self.running = False

        # Statistics
        self.total_anomalies = 0
        self.forensics_triggered = 0

    def start(self):
        """Start the auto-forensics engine"""
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def stop(self):
        """Stop all monitoring and debugging"""
        self.running = False

        # Stop all active tracers
        for tracers in self.active_tracers.values():
            for tracer in tracers:
                if hasattr(tracer, 'stop'):
                    tracer.stop()

        self.active_tracers.clear()

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Get all processes
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                    try:
                        # Update baseline
                        self.detector.update_baseline(proc)

                        # Detect anomalies
                        anomalies = self.detector.detect_anomalies(proc)

                        if anomalies:
                            self.total_anomalies += len(anomalies)

                            for anomaly in anomalies:
                                self._handle_anomaly(anomaly)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                time.sleep(5)  # Check every 5 seconds

            except Exception as e:
                print(f"Monitor loop error: {e}")
                time.sleep(5)

    def _handle_anomaly(self, anomaly: Anomaly):
        """Handle a detected anomaly by triggering appropriate forensics"""

        # Avoid duplicate forensics for same PID
        if anomaly.pid in self.active_tracers:
            return

        print(f"🔍 Anomaly detected: {anomaly.description} (PID={anomaly.pid})")

        # Create event to notify UI
        ui_event = TraceEvent(
            timestamp=anomaly.timestamp,
            tool="auto-forensics",
            pid=anomaly.pid,
            event_type=f"anomaly_{anomaly.type.value}",
            data={
                "process": anomaly.process_name,
                "description": anomaly.description,
                "metrics": anomaly.metrics
            },
            severity=anomaly.severity
        )
        self.on_forensics_event(ui_event)

        # Trigger appropriate debugging based on anomaly type
        tracers = []

        if anomaly.type == AnomalyType.HIGH_CPU:
            # Profile CPU usage
            profiler = PerfProfiler(self.on_forensics_event)
            threading.Thread(
                target=profiler.profile_cpu_hotspots,
                args=(anomaly.pid, 10),
                daemon=True
            ).start()
            tracers.append(profiler)

        elif anomaly.type == AnomalyType.HIGH_MEMORY or anomaly.type == AnomalyType.MEMORY_LEAK:
            # Profile memory
            profiler = MemoryProfiler(self.on_forensics_event)
            threading.Thread(
                target=profiler.profile_memory_leaks,
                args=(anomaly.pid, 30),
                daemon=True
            ).start()

            # Also trace memory syscalls
            tracer = BPFTracer(self.on_forensics_event)
            threading.Thread(
                target=tracer.trace_memory_anomalies,
                args=(anomaly.pid,),
                daemon=True
            ).start()
            tracers.extend([profiler, tracer])

        elif anomaly.type in (AnomalyType.SUSPICIOUS_NETWORK, AnomalyType.RAPID_CONNECTIONS):
            # Capture network traffic
            capture = NetworkCapture(self.on_forensics_event)
            capture.capture_process_traffic(anomaly.pid)

            # Trace network syscalls
            tracer = BPFTracer(self.on_forensics_event)
            threading.Thread(
                target=tracer.trace_network_anomalies,
                args=(anomaly.pid,),
                daemon=True
            ).start()
            tracers.extend([capture, tracer])

        elif anomaly.type == AnomalyType.CRYPTO_MINING:
            # Full forensics: strace + perf + network
            strace = StraceAnalyzer(self.on_forensics_event)
            strace.trace_suspicious_behavior(anomaly.pid)

            profiler = PerfProfiler(self.on_forensics_event)
            threading.Thread(
                target=profiler.profile_cpu_hotspots,
                args=(anomaly.pid, 15),
                daemon=True
            ).start()

            tracers.extend([strace, profiler])

        if tracers:
            self.active_tracers[anomaly.pid] = tracers
            self.forensics_triggered += 1

            # Auto-cleanup after 5 minutes
            threading.Timer(
                300,
                lambda: self._cleanup_tracers(anomaly.pid)
            ).start()

    def _cleanup_tracers(self, pid: int):
        """Cleanup tracers for a PID"""
        if pid in self.active_tracers:
            for tracer in self.active_tracers[pid]:
                if hasattr(tracer, 'stop'):
                    try:
                        tracer.stop()
                    except Exception:
                        pass

            del self.active_tracers[pid]
            print(f"✓ Forensics cleanup for PID {pid}")

    def get_statistics(self) -> Dict[str, any]:
        """Get engine statistics"""
        return {
            "total_anomalies": self.total_anomalies,
            "forensics_triggered": self.forensics_triggered,
            "active_investigations": len(self.active_tracers),
            "monitored_processes": len(self.detector.baselines)
        }
