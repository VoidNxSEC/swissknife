#!/usr/bin/env python3
"""
Swiss Btop - Context-Aware Process Monitor
Usage: swiss-btop [process_filter]
Example: swiss-btop brave
"""

import sys
import time
import psutil
import subprocess
import threading
from collections import deque
from datetime import datetime
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich.text import Text
from rich.style import Style

# Configuration
MAX_LOG_LINES = 20
REFRESH_RATE = 1.0

class ProcessContext:
    def __init__(self, filter_term="brave"):
        self.filter_term = filter_term
        self.logs = deque(maxlen=MAX_LOG_LINES)
        self.connections = []
        self.processes = []
        self.running = True
        
    def get_filtered_processes(self):
        """Find processes matching the filter"""
        procs = []
        try:
            for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'cmdline']):
                try:
                    # Check name or cmdline
                    cmdline = " ".join(p.info['cmdline'] or [])
                    if self.filter_term.lower() in p.info['name'].lower() or \
                       self.filter_term.lower() in cmdline.lower():
                        procs.append(p)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception:
            pass
        
        # Sort by CPU usage
        return sorted(procs, key=lambda x: x.info['cpu_percent'], reverse=True)

    def get_network_connections(self, pids):
        """Get network connections for the identified PIDs"""
        conns = []
        try:
            # Check global connections to avoid permission issues per-process if possible,
            # but usually need to check per process or run as root for full details.
            # Here we iterate identified processes.
            for p in self.processes:
                try:
                    p_conns = p.connections(kind='inet')
                    for c in p_conns:
                        if c.status == 'ESTABLISHED':
                            conns.append({
                                'pid': p.info['pid'],
                                'name': p.info['name'],
                                'local': f"{c.laddr.ip}:{c.laddr.port}",
                                'remote': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A",
                                'status': c.status
                            })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        except Exception:
            pass
        return conns

    def stream_journal_logs(self):
        """Stream logs from journalctl for the specific binary"""
        # Note: This filters by the executable name mostly
        cmd = ["journalctl", "-f", "-n", "50", "-o", "cat", f"_COMM={self.filter_term}"]
        if self.filter_term == "brave":
             # Brave processes might show up under slightly different names or we want everything related
             cmd = ["journalctl", "-f", "-n", "50", "-o", "cat", "|", "grep", "-i", self.filter_term]
             # Piping inside subprocess is tricky, let's stick to simple filter or grep in python
             cmd = ["journalctl", "-f", "-n", "20", "-o", "short-iso"]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        while self.running:
            line = process.stdout.readline()
            if line:
                # Simple python-side grep to ensure relevancy if journalctl filter is too broad
                if self.filter_term.lower() in line.lower():
                    self.logs.append(line.strip())
            else:
                time.sleep(0.1)

    def update_data(self):
        self.processes = self.get_filtered_processes()
        pids = [p.info['pid'] for p in self.processes]
        self.connections = self.get_network_connections(pids)

def generate_layout() -> Layout:
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=10)
    )
    layout["main"].split_row(
        Layout(name="processes", ratio=2),
        Layout(name="network", ratio=1)
    )
    return layout

def make_process_table(procs):
    table = Table(expand=True, border_style="blue")
    table.add_column("PID", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("CPU %", justify="right", style="green")
    table.add_column("MEM %", justify="right", style="yellow")
    table.add_column("Status", justify="center")

    total_cpu = 0.0
    total_mem = 0.0

    for p in procs[:20]: # Show top 20
        try:
            cpu = p.info['cpu_percent']
            mem = p.info['memory_percent']
            total_cpu += cpu
            total_mem += mem
            
            status_style = "green" if p.info['status'] == 'running' else "white"
            
            table.add_row(
                str(p.info['pid']),
                p.info['name'],
                f"{cpu:.1f}",
                f"{mem:.1f}",
                Text(p.info['status'], style=status_style)
            )
        except:
            continue
            
    return Panel(table, title=f"[b]Processes (Total CPU: {total_cpu:.1f}%)", border_style="blue")

def make_network_table(conns):
    table = Table(expand=True, border_style="cyan")
    table.add_column("PID", style="dim cyan")
    table.add_column("Remote Address", style="bold red")
    
    # Deduplicate somewhat
    seen = set()
    
    for c in conns:
        key = f"{c['remote']}"
        if key not in seen and c['remote'] != "N/A":
            seen.add(key)
            table.add_row(
                str(c['pid']),
                c['remote']
            )
            
    return Panel(table, title="[b]Active Connections", border_style="cyan")

def make_log_panel(logs):
    text = Text()
    for line in logs:
        # Highlight basic keywords
        line_text = Text(line)
        if "error" in line.lower():
            line_text.style = "bold red"
        elif "warn" in line.lower():
            line_text.style = "yellow"
        text.append(line_text)
        text.append("\n")
        
    return Panel(text, title="[b]Live Context Logs (Journald)", border_style="white")

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "brave"
    
    context = ProcessContext(target)
    
    # Start log thread
    log_thread = threading.Thread(target=context.stream_journal_logs, daemon=True)
    log_thread.start()
    
    console = Console()
    layout = generate_layout()
    
    layout["header"].update(Panel(Text(f"🇨🇭 Swiss Btop: Monitoring '{target}'", justify="center", style="bold white"), style="blue"))

    with Live(layout, refresh_per_second=1, screen=True):
        while True:
            try:
                context.update_data()
                
                layout["processes"].update(make_process_table(context.processes))
                layout["network"].update(make_network_table(context.connections))
                layout["footer"].update(make_log_panel(context.logs))
                
                time.sleep(REFRESH_RATE)
            except KeyboardInterrupt:
                context.running = False
                break

if __name__ == "__main__":
    main()
