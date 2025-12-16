#!/usr/bin/env python3
"""
Swiss Monitor GTK4 v2 - Professional SOC with Auto-Forensics

Advanced features:
- Auto-forensics engine with intelligent anomaly detection
- Real-time debugging integration (BPFTrace, Strace, Perf, etc.)
- Professional glassmorphism UI
- Live forensics dashboard
- AI-powered threat analysis
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

import json
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Callable, List

from gi.repository import Adw, Gio, GLib, Gtk, Pango
import psutil

# Auto-forensics imports
try:
    from auto_forensics import AutoForensicsEngine, Anomaly
    from debug_tools import TraceEvent
    HAS_FORENSICS = True
except ImportError:
    HAS_FORENSICS = False
    print("⚠️  Auto-forensics not available")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class Severity(Enum):
    CRITICAL = ("critical", "🔴", "#ff3333", "#1a0000")
    HIGH = ("high", "🟠", "#ff8c00", "#1a0a00")
    MEDIUM = ("medium", "🟡", "#ffd700", "#1a1a00")
    LOW = ("low", "🔵", "#4da6ff", "#00081a")
    INFO = ("info", "⚪", "#888888", "#0a0a0a")

    @property
    def icon(self) -> str:
        return self.value[1]

    @property
    def color(self) -> str:
        return self.value[2]

    @property
    def bg_color(self) -> str:
        return self.value[3]


@dataclass
class LogEvent:
    """Security log event"""
    timestamp: str
    source: str
    message: str
    severity: Severity = Severity.INFO
    category: str = ""
    pid: Optional[int] = None


class ForensicsCard(Gtk.Box):
    """Professional card widget for forensics events"""

    def __init__(self, event: TraceEvent):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.set_margin_top(8)
        self.set_margin_bottom(8)
        self.set_margin_start(12)
        self.set_margin_end(12)

        # Determine severity
        severity_map = {
            "critical": Severity.CRITICAL,
            "warning": Severity.HIGH,
            "info": Severity.INFO
        }
        severity = severity_map.get(event.severity, Severity.INFO)

        # Add card styling
        self.add_css_class("card")
        self.add_css_class("forensics-card")

        # Header with icon and tool name
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.append(header_box)

        icon_label = Gtk.Label(label=severity.icon)
        icon_label.add_css_class("title-1")
        header_box.append(icon_label)

        tool_label = Gtk.Label(label=event.tool.upper())
        tool_label.add_css_class("heading")
        tool_label.add_css_class("accent")
        tool_label.set_hexpand(True)
        tool_label.set_halign(Gtk.Align.START)
        header_box.append(tool_label)

        # PID badge
        pid_label = Gtk.Label(label=f"PID:{event.pid}")
        pid_label.add_css_class("pill")
        pid_label.add_css_class("dim-label")
        header_box.append(pid_label)

        # Event type
        event_type_label = Gtk.Label(label=event.event_type)
        event_type_label.add_css_class("title-4")
        event_type_label.set_halign(Gtk.Align.START)
        self.append(event_type_label)

        # Data display
        if event.data:
            data_frame = Gtk.Frame()
            data_frame.add_css_class("view")

            data_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            data_box.set_margin_top(8)
            data_box.set_margin_bottom(8)
            data_box.set_margin_start(8)
            data_box.set_margin_end(8)
            data_frame.set_child(data_box)

            for key, value in list(event.data.items())[:5]:  # Show max 5 items
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

                key_label = Gtk.Label(label=f"{key}:")
                key_label.add_css_class("dim-label")
                key_label.set_halign(Gtk.Align.START)
                key_label.set_size_request(100, -1)
                row.append(key_label)

                value_str = str(value)[:100]  # Truncate long values
                value_label = Gtk.Label(label=value_str)
                value_label.set_halign(Gtk.Align.START)
                value_label.set_ellipsize(Pango.EllipsizeMode.END)
                value_label.set_hexpand(True)
                value_label.add_css_class("monospace")
                row.append(value_label)

                data_box.append(row)

            self.append(data_frame)

        # Timestamp
        time_label = Gtk.Label(label=event.timestamp)
        time_label.add_css_class("caption")
        time_label.add_css_class("dim-label")
        time_label.set_halign(Gtk.Align.END)
        self.append(time_label)


class ForensicsDashboard(Gtk.ScrolledWindow):
    """Live forensics dashboard showing debug tool outputs"""

    def __init__(self):
        super().__init__()
        self.set_vexpand(True)
        self.set_hexpand(True)
        self.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        # Main container
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.main_box.set_margin_top(12)
        self.main_box.set_margin_bottom(12)
        self.main_box.set_margin_start(12)
        self.main_box.set_margin_end(12)
        self.set_child(self.main_box)

        # Header
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.main_box.append(header)

        title = Gtk.Label(label="🔬 Auto-Forensics Dashboard")
        title.add_css_class("title-2")
        title.set_hexpand(True)
        title.set_halign(Gtk.Align.START)
        header.append(title)

        # Stats badges
        self.stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.append(self.stats_box)

        self.anomaly_badge = self._create_badge("0 Anomalies", "warning")
        self.stats_box.append(self.anomaly_badge)

        self.forensics_badge = self._create_badge("0 Active", "accent")
        self.stats_box.append(self.forensics_badge)

        # Events container
        self.events_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.main_box.append(self.events_box)

        self.max_events = 50

    def _create_badge(self, text: str, css_class: str) -> Gtk.Label:
        label = Gtk.Label(label=text)
        label.add_css_class("pill")
        label.add_css_class(css_class)
        return label

    def add_forensics_event(self, event: TraceEvent):
        """Add a forensics event card"""
        card = ForensicsCard(event)
        self.events_box.prepend(card)

        # Limit events
        children = []
        child = self.events_box.get_first_child()
        while child:
            children.append(child)
            child = child.get_next_sibling()

        if len(children) > self.max_events:
            self.events_box.remove(children[-1])

    def update_stats(self, anomalies: int, active: int):
        """Update statistics badges"""
        self.anomaly_badge.set_text(f"{anomalies} Anomalies")
        self.forensics_badge.set_text(f"{active} Active")


class SystemStatsPanel(Gtk.Box):
    """Compact system statistics panel"""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(12)
        self.set_margin_end(12)

        # Title
        title = Gtk.Label(label="⚡ System Vitals")
        title.add_css_class("title-3")
        title.set_halign(Gtk.Align.START)
        self.append(title)

        # Create stat cards
        self.cpu_card = self._create_stat_card("CPU", "0%", Severity.INFO)
        self.append(self.cpu_card)

        self.mem_card = self._create_stat_card("Memory", "0%", Severity.INFO)
        self.append(self.mem_card)

        self.net_card = self._create_stat_card("Network", "0 conn", Severity.INFO)
        self.append(self.net_card)

        self.disk_card = self._create_stat_card("Disk I/O", "0 MB/s", Severity.INFO)
        self.append(self.disk_card)

    def _create_stat_card(self, name: str, value: str, severity: Severity):
        """Create a stat card"""
        frame = Gtk.Frame()
        frame.add_css_class("card")

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(12)
        box.set_margin_end(12)
        frame.set_child(box)

        name_label = Gtk.Label(label=name)
        name_label.add_css_class("caption")
        name_label.add_css_class("dim-label")
        name_label.set_halign(Gtk.Align.START)
        box.append(name_label)

        value_label = Gtk.Label(label=value)
        value_label.add_css_class("title-1")
        value_label.set_halign(Gtk.Align.START)
        box.append(value_label)

        # Store reference
        frame.value_label = value_label
        frame.severity = severity

        return frame

    def update(self, cpu: float, mem: float, conns: int, disk_io: float):
        """Update stats"""
        # CPU
        self.cpu_card.value_label.set_text(f"{cpu:.1f}%")
        if cpu > 80:
            self.cpu_card.severity = Severity.CRITICAL
        elif cpu > 50:
            self.cpu_card.severity = Severity.HIGH
        else:
            self.cpu_card.severity = Severity.INFO

        # Memory
        self.mem_card.value_label.set_text(f"{mem:.1f}%")
        if mem > 90:
            self.mem_card.severity = Severity.CRITICAL
        elif mem > 70:
            self.mem_card.severity = Severity.HIGH

        # Network
        self.net_card.value_label.set_text(f"{conns} conn")
        if conns > 100:
            self.net_card.severity = Severity.HIGH

        # Disk
        self.disk_card.value_label.set_text(f"{disk_io:.1f} MB/s")


class CompactLogView(Gtk.ScrolledWindow):
    """Compact log view with professional styling"""

    def __init__(self, title: str = "Logs"):
        super().__init__()
        self.set_vexpand(True)
        self.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.set_child(box)

        # Header
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.set_margin_start(12)
        header.set_margin_end(12)
        header.set_margin_top(8)
        header.set_margin_bottom(8)
        header.add_css_class("toolbar")
        box.append(header)

        label = Gtk.Label(label=title)
        label.add_css_class("title-4")
        header.append(label)

        # List
        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.list_box.add_css_class("boxed-list")
        box.append(self.list_box)

        self.max_entries = 100

    def add_log(self, event: LogEvent):
        """Add log entry"""
        row = Gtk.ListBoxRow()
        row.set_activatable(False)

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.set_margin_top(4)
        box.set_margin_bottom(4)
        box.set_margin_start(8)
        box.set_margin_end(8)
        row.set_child(box)

        # Severity
        icon = Gtk.Label(label=event.severity.icon)
        box.append(icon)

        # Time
        time_str = event.timestamp[11:19] if len(event.timestamp) > 11 else event.timestamp
        time_label = Gtk.Label(label=time_str)
        time_label.add_css_class("monospace")
        time_label.add_css_class("dim-label")
        box.append(time_label)

        # Source
        source_label = Gtk.Label(label=f"[{event.source[:15]}]")
        source_label.add_css_class("accent")
        box.append(source_label)

        # Message
        msg_label = Gtk.Label(label=event.message[:80])
        msg_label.set_ellipsize(Pango.EllipsizeMode.END)
        msg_label.set_hexpand(True)
        msg_label.set_halign(Gtk.Align.START)
        box.append(msg_label)

        # Severity styling
        if event.severity == Severity.CRITICAL:
            row.add_css_class("error")
        elif event.severity == Severity.HIGH:
            row.add_css_class("warning")

        self.list_box.prepend(row)

        # Limit
        while len(list(self.list_box)) > self.max_entries:
            last = self.list_box.get_row_at_index(self.max_entries)
            if last:
                self.list_box.remove(last)


class SwissMonitorWindow(Adw.ApplicationWindow):
    """Main window with auto-forensics integration"""

    def __init__(self, app: Adw.Application):
        super().__init__(application=app)

        self.set_title("🇨🇭 Swiss Monitor SOC v2")
        self.set_default_size(1400, 900)

        # Main container
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(main_box)

        # Header
        header = Adw.HeaderBar()
        main_box.append(header)

        # View switcher in header
        self.stack = Adw.ViewStack()
        switcher = Adw.ViewSwitcher()
        switcher.set_stack(self.stack)
        switcher.set_policy(Adw.ViewSwitcherPolicy.WIDE)
        header.set_title_widget(switcher)

        # Content layout
        content_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        main_box.append(content_box)

        # Left sidebar - stats
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        sidebar.set_size_request(280, -1)
        sidebar.add_css_class("sidebar")
        content_box.append(sidebar)

        self.stats_panel = SystemStatsPanel()
        sidebar.append(self.stats_panel)

        # Separator
        sep = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
        content_box.append(sep)

        # Main content
        content_box.append(self.stack)
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)

        # === TABS ===

        # Forensics Dashboard (Main tab)
        self.forensics_dashboard = ForensicsDashboard()
        self.stack.add_titled(self.forensics_dashboard, "forensics", "🔬 Forensics")

        # Security Logs
        self.security_logs = CompactLogView("🛡️ Security Events")
        self.stack.add_titled(self.security_logs, "security", "🛡️ Security")

        # System Logs
        self.system_logs = CompactLogView("📋 System Logs")
        self.stack.add_titled(self.system_logs, "system", "📋 System")

        # Start monitoring
        self._start_monitoring()

        # Start auto-forensics
        if HAS_FORENSICS:
            self.forensics_engine = AutoForensicsEngine(self._on_forensics_event)
            self.forensics_engine.start()
            print("✓ Auto-forensics engine started")
        else:
            self.forensics_engine = None

    def _start_monitoring(self):
        """Start background monitoring"""
        threading.Thread(target=self._stats_loop, daemon=True).start()
        threading.Thread(target=self._journald_loop, daemon=True).start()

    def _stats_loop(self):
        """Update system stats"""
        import time
        last_io = psutil.disk_io_counters()

        while True:
            try:
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory().percent
                conns = len(psutil.net_connections())

                # Disk I/O rate
                current_io = psutil.disk_io_counters()
                io_mb = (current_io.read_bytes + current_io.write_bytes -
                         last_io.read_bytes - last_io.write_bytes) / 1024 / 1024
                last_io = current_io

                GLib.idle_add(self.stats_panel.update, cpu, mem, conns, io_mb)

                # Update forensics stats if available
                if self.forensics_engine:
                    stats = self.forensics_engine.get_statistics()
                    GLib.idle_add(
                        self.forensics_dashboard.update_stats,
                        stats['total_anomalies'],
                        stats['active_investigations']
                    )

            except Exception as e:
                print(f"Stats error: {e}")

            time.sleep(2)

    def _journald_loop(self):
        """Stream system logs"""
        proc = subprocess.Popen(
            ["journalctl", "-f", "-o", "json", "-p", "notice"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )

        for line in proc.stdout:
            try:
                data = json.loads(line.decode())
                priority = int(data.get("PRIORITY", 6))

                severity_map = {
                    0: Severity.CRITICAL, 1: Severity.CRITICAL, 2: Severity.CRITICAL,
                    3: Severity.HIGH, 4: Severity.MEDIUM, 5: Severity.LOW
                }
                severity = severity_map.get(priority, Severity.INFO)

                event = LogEvent(
                    timestamp=datetime.now().isoformat(),
                    source=data.get("_SYSTEMD_UNIT", "system")[:20],
                    message=data.get("MESSAGE", "")[:150],
                    severity=severity
                )

                GLib.idle_add(self.system_logs.add_log, event)

                if severity in (Severity.CRITICAL, Severity.HIGH):
                    GLib.idle_add(self.security_logs.add_log, event)

            except (json.JSONDecodeError, ValueError):
                continue

    def _on_forensics_event(self, event: TraceEvent):
        """Handle forensics events from auto-forensics engine"""
        GLib.idle_add(self.forensics_dashboard.add_forensics_event, event)

        # Also log to security if it's a critical event
        if event.severity == "critical":
            log_event = LogEvent(
                timestamp=event.timestamp,
                source=f"forensics/{event.tool}",
                message=f"[PID:{event.pid}] {event.event_type}: {event.data.get('description', '')}",
                severity=Severity.CRITICAL,
                pid=event.pid
            )
            GLib.idle_add(self.security_logs.add_log, log_event)


class SwissMonitorApp(Adw.Application):
    """Main application"""

    def __init__(self):
        super().__init__(
            application_id="com.voidnxsec.swiss-monitor-v2",
            flags=Gio.ApplicationFlags.FLAGS_NONE
        )

    def do_activate(self):
        win = SwissMonitorWindow(self)
        win.present()


def main():
    if not HAS_FORENSICS:
        print("⚠️  Warning: Auto-forensics modules not found")
        print("   Some features will be limited")

    app = SwissMonitorApp()
    app.run(sys.argv)


if __name__ == "__main__":
    main()
