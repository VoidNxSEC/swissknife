import sys
import subprocess
import time
import json
import psutil
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

console = Console()

def get_system_stats():
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    return cpu, mem, disk

def get_recent_process_anomalies():
    # Placeholder: In real implementation, this would scan process list for high resource usage
    anomalies = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent']):
        try:
            if proc.info['cpu_percent'] > 80:
                anomalies.append(f"High CPU: {proc.info['name']} ({proc.info['pid']}) - {proc.info['cpu_percent']}%")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return anomalies

def run_monitor():
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=3)
    )
    
    layout["body"].split_row(
        Layout(name="stats", ratio=1),
        Layout(name="logs", ratio=2)
    )

    header = Panel("[bold white]🇨🇭 Swiss Monitor - Real-Time Intelligence[/]", style="on blue")
    layout["header"].update(header)

    with Live(layout, refresh_per_second=2) as live:
        try:
            while True:
                # Update Stats
                cpu, mem, disk = get_system_stats()
                
                stats_table = Table(title="System Vital Signs")
                stats_table.add_column("Metric")
                stats_table.add_column("Value")
                
                cpu_style = "green" if cpu < 50 else "yellow" if cpu < 80 else "red"
                mem_style = "green" if mem < 60 else "yellow" if mem < 85 else "red"
                
                stats_table.add_row("CPU Usage", f"[{cpu_style}]{cpu}%[/]")
                stats_table.add_row("Memory", f"[{mem_style}]{mem}%[/]")
                stats_table.add_row("Disk '/'", f"{disk}%")
                
                anomalies = get_recent_process_anomalies()
                if anomalies:
                    stats_table.add_section()
                    for a in anomalies:
                        stats_table.add_row("⚠️ Anomaly", f"[red]{a}[/]")
                
                layout["stats"].update(Panel(stats_table, border_style="cyan"))
                
                # Fetch Logs (Simulated stream for now, would replace 'journalctl -f')
                # In full version this reads from a thread streaming journalctl
                layout["logs"].update(Panel("Waiting for system events...", title="Live Journal Analysis"))
                
                time.sleep(1)
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    run_monitor()
