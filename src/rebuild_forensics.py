import sys
import os
import subprocess
import time
import json
import re
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.logging import RichHandler
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import logging

# Configuration
LOG_DIR = f"/tmp/swiss-rebuild-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
os.makedirs(LOG_DIR, exist_ok=True)

console = Console()
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, markup=True)]
)
log = logging.getLogger("swiss-rebuild")

def get_rebuild_cmd():
    return ["sudo", "nixos-rebuild", "switch", "--flake", "/etc/nixos#kernelcore", "--verbose", "--show-trace"]

def parse_line(line):
    """
    Parse a line of output to extract meaningful info.
    Returns (type, message)
    """
    line = line.strip()
    if not line:
        return None, None
        
    if "error:" in line.lower():
        return "ERROR", line
    if "warning:" in line.lower():
        return "WARNING", line
    if "building" in line.lower() and ".drv" in line:
        return "BUILD", line
    if "copying" in line.lower():
        return "COPY", line
    if "starting" in line.lower():
        return "SERVICE", line
        
    return "INFO", line

def run_rebuild():
    cmd = get_rebuild_cmd()
    log.info(f"Starting rebuild: [bold cyan]{' '.join(cmd)}[/]")
    
    # UI Setup
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=3)
    )
    
    header_text = Text("🇨🇭 Swiss Rebuild Forensics", justify="center", style="bold white on blue")
    layout["header"].update(Panel(header_text))
    
    logs_text = Text()
    layout["main"].update(Panel(logs_text, title="Live Logs", border_style="blue"))
    
    status_text = Text("Initializing...", style="yellow")
    layout["footer"].update(Panel(status_text, title="Status"))

    with Live(layout, refresh_per_second=4) as live:
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            start_time = time.time()
            error_buffer = []
            
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if line:
                    msg_type, msg = parse_line(line)
                    if not msg:
                        continue
                        
                    # Colorize based on type
                    style = "white"
                    if msg_type == "ERROR":
                        style = "bold red"
                        error_buffer.append(msg)
                        status_text = Text(f"ERROR DETECTED: {msg[:50]}...", style="bold red blink")
                    elif msg_type == "WARNING":
                        style = "yellow"
                    elif msg_type == "BUILD":
                        style = "cyan"
                        status_text = Text(f"Building: {msg.split()[-1][:40]}...", style="cyan")
                    elif msg_type == "SERVICE":
                        style = "green"
                        status_text = Text(f"Service: {msg}", style="green")
                        
                    logs_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n", style=style)
                    
                    # Keep log buffer reasonable
                    if len(logs_text._text) > 50: # Simplification for Text object
                         pass # Rich Text doesn't work exactly like list, but we rely on scrolling behavior of Panel if we output it right

                    layout["main"].update(Panel(logs_text, title="Live Logs", border_style="blue"))
                    layout["footer"].update(Panel(status_text, title="Status"))

            rc = process.poll()
            duration = time.time() - start_time
            
            if rc == 0:
                final_msg = f"✅ Rebuild Successful in {duration:.2f}s"
                layout["footer"].update(Panel(Text(final_msg, style="bold green")))
            else:
                final_msg = f"❌ Rebuild Failed (RC={rc}) in {duration:.2f}s"
                layout["footer"].update(Panel(Text(final_msg, style="bold red")))
                
                # Here we would trigger ML analysis on error_buffer
                if error_buffer:
                    analyze_errors(error_buffer)

        except Exception as e:
            log.error(f"Critical execution error: {e}")

def analyze_errors(errors):
    """
    Placeholder for ML analysis
    """
    console.print(Panel("\n".join(errors), title="[bold red]Forensic Analysis Required[/]", border_style="red"))
    console.print("[yellow]Tip: Run 'swiss-doctor' to diagnose service failures.[/]")

if __name__ == "__main__":
    if os.geteuid() != 0:
        console.print("[bold red]Error:[/] This tool must be run as root (sudo).")
        sys.exit(1)
        
    run_rebuild()
