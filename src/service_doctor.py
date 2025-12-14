import sys
import subprocess
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        return None

def get_failed_units():
    """
    Get list of failed systemd units
    """
    output = run_cmd("systemctl list-units --state=failed --output=json")
    if not output:
        return []
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        # Fallback for older systemd versions
        return []

def analyze_unit(unit_name):
    """
    Deep dive into a unit
    """
    console.print(f"\n[bold cyan]Analyzing {unit_name}...[/]")
    
    # Get status
    status = run_cmd(f"systemctl status {unit_name} -n 20 --no-pager")
    if status:
        console.print(Panel(status, title="Systemd Status", border_style="blue"))
    
    # Get logs
    logs = run_cmd(f"journalctl -u {unit_name} -n 50 --no-pager --output=short-iso")
    if logs:
        # Simple heuristic analysis
        errors = []
        for line in logs.splitlines():
            if "error" in line.lower() or "failed" in line.lower() or "denied" in line.lower():
                errors.append(line)
        
        if errors:
            console.print(Panel("\n".join(errors[-10:]), title="[red]Recent Errors Detected[/]", border_style="red"))
            
            # Advice generation (Placeholder for ML)
            advice = generate_advice(unit_name, errors)
            console.print(Panel(Markdown(advice), title="[green]Dr. Swiss Prescription[/]", border_style="green"))
        else:
             console.print("[yellow]No obvious errors found in recent logs.[/]")

def generate_advice(unit, errors):
    """
    Simple heuristic advice generator
    """
    advice = f"### Diagnosis for {unit}\n\n"
    
    err_text = " ".join(errors).lower()
    
    if "exit-code" in err_text:
        advice += "- **Crash Detected**: The process exited with an error code. Check the binary arguments.\n"
    if "permission denied" in err_text:
        advice += "- **Permissions Issue**: Check filesystem permissions or Security hardening settings.\n"
    if "address already in use" in err_text:
        advice += "- **Port Conflict**: Another service is using the bound port.\n"
    if "timeout" in err_text:
        advice += "- **Timeout**: The service took too long to start. It might be hanging.\n"
        
    advice += "\n**Recommended Action:**\nRun `journalctl -u {unit} -f` and restart the service to see live errors."
    return advice

def main():
    console.print("[bold white on blue] 🇨🇭 Swiss Doctor - Service Diagnostic Tool [/]")
    
    # Check for specific units if args provided
    if len(sys.argv) > 1:
        target_units = sys.argv[1:]
        console.print(f"Diagnosing specific units: {', '.join(target_units)}")
        for unit in target_units:
            analyze_unit(unit)
        return

    # Auto-detect failed
    console.print("Scanning for failed services...")
    failed = get_failed_units()
    
    if not failed:
        console.print("[bold green]✅ No failed systemd units found![/]")
        return
        
    table = Table(title=f"Failed Units Detected ({len(failed)})")
    table.add_column("Unit", style="cyan")
    table.add_column("Load", style="magenta")
    table.add_column("Active", style="red")
    table.add_column("Sub", style="yellow")
    table.add_column("Description")
    
    for u in failed:
        table.add_row(u['unit'], u['load'], u['active'], u['sub'], u['description'])
    
    console.print(table)
    
    if console.input("\n[bold yellow]Do you want to diagnose these units? (y/n): [/]").lower() == 'y':
        for u in failed:
            analyze_unit(u['unit'])

if __name__ == "__main__":
    main()
