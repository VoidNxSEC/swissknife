#!/usr/bin/env python3
"""
Swiss Monitor GTK4 - Native SOC Monitor for Wayland

A professional GTK4/Adwaita application for real-time security monitoring:
- Native Wayland integration
- Glassmorphism styling with libadwaita
- Real-time log streaming from journald, Suricata, FIM
- LLM chat for emergency assistance (llama.cpp turbo)
- System tray integration

Run: swiss-monitor
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

import asyncio
import json
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Callable

from gi.repository import Adw, Gio, GLib, Gtk, Pango
import psutil

# Try to import aiohttp for LLM
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


class Severity(Enum):
    CRITICAL = ("critical", "🔴", "#ff3333")
    HIGH = ("high", "🟠", "#ff8c00")
    MEDIUM = ("medium", "🟡", "#ffd700")
    LOW = ("low", "🔵", "#4da6ff")
    INFO = ("info", "⚪", "#888888")

    @property
    def icon(self) -> str:
        return self.value[1]

    @property
    def color(self) -> str:
        return self.value[2]


@dataclass
class LogEvent:
    """Represents a security log event"""
    timestamp: str
    source: str
    message: str
    severity: Severity = Severity.INFO
    category: str = ""


class StatsWidget(Gtk.Box):
    """System statistics widget"""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(12)
        self.set_margin_end(12)

        # Title
        title = Gtk.Label(label="System Vitals")
        title.add_css_class("title-4")
        self.append(title)

        # Stats grid
        self.grid = Gtk.Grid()
        self.grid.set_column_spacing(12)
        self.grid.set_row_spacing(6)
        self.append(self.grid)

        # Create labels
        self.cpu_label = self._add_stat_row("CPU:", 0)
        self.mem_label = self._add_stat_row("RAM:", 1)
        self.disk_label = self._add_stat_row("Disk:", 2)
        self.swap_label = self._add_stat_row("Swap:", 3)
        self.conns_label = self._add_stat_row("Connections:", 4)

        # Progress bars
        self.cpu_bar = self._add_progress_bar(0)
        self.mem_bar = self._add_progress_bar(1)
        self.disk_bar = self._add_progress_bar(2)
        self.swap_bar = self._add_progress_bar(3)

    def _add_stat_row(self, label: str, row: int) -> Gtk.Label:
        name = Gtk.Label(label=label)
        name.set_halign(Gtk.Align.START)
        name.add_css_class("dim-label")
        self.grid.attach(name, 0, row, 1, 1)

        value = Gtk.Label(label="--")
        value.set_halign(Gtk.Align.END)
        value.set_hexpand(True)
        self.grid.attach(value, 2, row, 1, 1)
        return value

    def _add_progress_bar(self, row: int) -> Gtk.LevelBar:
        bar = Gtk.LevelBar()
        bar.set_min_value(0)
        bar.set_max_value(100)
        bar.set_hexpand(True)
        bar.set_size_request(100, -1)
        self.grid.attach(bar, 1, row, 1, 1)
        return bar

    def update(self, cpu: float, mem: float, disk: float, swap: float, conns: int):
        self.cpu_label.set_text(f"{cpu:.1f}%")
        self.mem_label.set_text(f"{mem:.1f}%")
        self.disk_label.set_text(f"{disk:.1f}%")
        self.swap_label.set_text(f"{swap:.1f}%")
        self.conns_label.set_text(str(conns))

        self.cpu_bar.set_value(cpu)
        self.mem_bar.set_value(mem)
        self.disk_bar.set_value(disk)
        self.swap_bar.set_value(swap)


class LogView(Gtk.ScrolledWindow):
    """Scrollable log view with colored entries"""

    def __init__(self, title: str = "Logs"):
        super().__init__()
        self.set_vexpand(True)
        self.set_hexpand(True)
        self.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        # Main container
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.set_child(box)

        # Title bar
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        header.add_css_class("toolbar")
        header.set_margin_start(6)
        header.set_margin_end(6)

        label = Gtk.Label(label=title)
        label.add_css_class("heading")
        header.append(label)
        box.append(header)

        # Log list
        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.list_box.add_css_class("rich-list")
        box.append(self.list_box)

        self.max_entries = 200

    def add_log(self, event: LogEvent):
        """Add a log entry"""
        row = Gtk.ListBoxRow()
        row.set_activatable(False)

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.set_margin_top(4)
        box.set_margin_bottom(4)
        box.set_margin_start(8)
        box.set_margin_end(8)
        row.set_child(box)

        # Severity icon
        icon = Gtk.Label(label=event.severity.icon)
        box.append(icon)

        # Timestamp
        time_str = event.timestamp[11:19] if len(event.timestamp) > 11 else event.timestamp
        time_label = Gtk.Label(label=time_str)
        time_label.add_css_class("dim-label")
        time_label.add_css_class("monospace")
        box.append(time_label)

        # Source
        source_label = Gtk.Label(label=f"[{event.source}]")
        source_label.add_css_class("accent")
        source_label.set_max_width_chars(20)
        source_label.set_ellipsize(Pango.EllipsizeMode.END)
        box.append(source_label)

        # Message
        msg_label = Gtk.Label(label=event.message)
        msg_label.set_hexpand(True)
        msg_label.set_halign(Gtk.Align.START)
        msg_label.set_ellipsize(Pango.EllipsizeMode.END)
        msg_label.set_max_width_chars(80)
        box.append(msg_label)

        # Color based on severity
        if event.severity == Severity.CRITICAL:
            row.add_css_class("error")
        elif event.severity == Severity.HIGH:
            row.add_css_class("warning")

        self.list_box.prepend(row)

        # Limit entries
        while len(list(self.list_box)) > self.max_entries:
            last = self.list_box.get_row_at_index(self.max_entries)
            if last:
                self.list_box.remove(last)

    def clear(self):
        """Clear all logs"""
        while True:
            row = self.list_box.get_row_at_index(0)
            if row:
                self.list_box.remove(row)
            else:
                break


class ChatWidget(Gtk.Box):
    """LLM Chat widget for emergency assistance"""

    def __init__(self, on_send: Callable[[str], None]):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.set_margin_top(8)
        self.set_margin_bottom(8)
        self.set_margin_start(8)
        self.set_margin_end(8)

        self.on_send = on_send

        # Chat history
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.append(scroll)

        self.chat_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        scroll.set_child(self.chat_box)

        # Input area
        input_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.append(input_box)

        self.entry = Gtk.Entry()
        self.entry.set_placeholder_text("Ask about security events...")
        self.entry.set_hexpand(True)
        self.entry.connect("activate", self._on_send)
        input_box.append(self.entry)

        send_btn = Gtk.Button(label="Send")
        send_btn.add_css_class("suggested-action")
        send_btn.connect("clicked", self._on_send)
        input_box.append(send_btn)

    def _on_send(self, _widget):
        text = self.entry.get_text().strip()
        if text:
            self.add_message("You", text, is_user=True)
            self.entry.set_text("")
            self.on_send(text)

    def add_message(self, sender: str, message: str, is_user: bool = False):
        """Add a chat message"""
        frame = Gtk.Frame()
        frame.set_margin_top(4)
        frame.set_margin_bottom(4)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(8)
        box.set_margin_end(8)
        frame.set_child(box)

        # Sender
        sender_label = Gtk.Label(label=sender)
        sender_label.set_halign(Gtk.Align.START)
        sender_label.add_css_class("heading")
        if is_user:
            sender_label.add_css_class("accent")
        box.append(sender_label)

        # Message
        msg_label = Gtk.Label(label=message)
        msg_label.set_halign(Gtk.Align.START)
        msg_label.set_wrap(True)
        msg_label.set_max_width_chars(60)
        box.append(msg_label)

        self.chat_box.append(frame)


class ActionsWidget(Gtk.Box):
    """Quick actions panel"""

    def __init__(self, on_action: Callable[[str], None]):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(12)
        self.set_margin_end(12)

        self.on_action = on_action

        # Title
        title = Gtk.Label(label="⚡ Quick Actions")
        title.add_css_class("title-4")
        self.append(title)

        # Buttons
        self._add_button("🔍 Analyze Threats", "analyze", "suggested-action")
        self._add_button("🛡️ Check Suricata", "suricata")
        self._add_button("📊 System Status", "status")
        self._add_button("🔄 Refresh", "refresh")
        self._add_button("🧹 Clear Logs", "clear")

        # Spacer
        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        self.append(spacer)

        # Emergency button
        emergency = Gtk.Button(label="🚨 EMERGENCY")
        emergency.add_css_class("destructive-action")
        emergency.connect("clicked", lambda _: self.on_action("emergency"))
        self.append(emergency)

    def _add_button(self, label: str, action: str, css_class: str = None):
        btn = Gtk.Button(label=label)
        if css_class:
            btn.add_css_class(css_class)
        btn.connect("clicked", lambda _: self.on_action(action))
        self.append(btn)


class SwissMonitorWindow(Adw.ApplicationWindow):
    """Main window"""

    def __init__(self, app: Adw.Application):
        super().__init__(application=app)

        self.set_title("🇨🇭 Swiss Monitor SOC")
        self.set_default_size(1200, 800)

        # Main layout
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(self.main_box)

        # Header bar
        header = Adw.HeaderBar()
        self.main_box.append(header)

        # Title
        title = Adw.WindowTitle(title="🇨🇭 Swiss Monitor", subtitle="Security Operations Center")
        header.set_title_widget(title)

        # View switcher
        self.stack = Adw.ViewStack()

        switcher = Adw.ViewSwitcher()
        switcher.set_stack(self.stack)
        switcher.set_policy(Adw.ViewSwitcherPolicy.WIDE)
        header.set_title_widget(switcher)

        # Content
        content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        content.set_hexpand(True)
        content.set_vexpand(True)
        self.main_box.append(content)

        # Left sidebar - Stats
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        sidebar.set_size_request(250, -1)
        sidebar.add_css_class("sidebar")
        content.append(sidebar)

        self.stats = StatsWidget()
        sidebar.append(self.stats)

        self.actions = ActionsWidget(self._on_action)
        sidebar.append(self.actions)

        # Separator
        sep = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
        content.append(sep)

        # Main content area with tabs
        content.append(self.stack)
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)

        # Dashboard tab
        dashboard = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        self.stack.add_titled(dashboard, "dashboard", "📊 Dashboard")

        self.logs_view = LogView("System Logs")
        dashboard.set_start_child(self.logs_view)

        self.alerts_view = LogView("Security Alerts")
        self.alerts_view.add_css_class("error")
        dashboard.set_end_child(self.alerts_view)
        dashboard.set_position(400)

        # Chat tab
        self.chat = ChatWidget(self._on_chat_send)
        self.stack.add_titled(self.chat, "chat", "💬 AI Assistant")

        # Suricata tab
        self.suricata_view = LogView("Suricata IDS")
        self.stack.add_titled(self.suricata_view, "suricata", "📈 Suricata")

        # Start background threads
        self._start_monitoring()

    def _start_monitoring(self):
        """Start background monitoring threads"""
        threading.Thread(target=self._stats_loop, daemon=True).start()
        threading.Thread(target=self._journald_loop, daemon=True).start()
        threading.Thread(target=self._suricata_loop, daemon=True).start()

    def _stats_loop(self):
        """Update stats periodically"""
        import time
        while True:
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory().percent
                disk = psutil.disk_usage('/').percent
                swap = psutil.swap_memory().percent
                conns = len(psutil.net_connections())

                GLib.idle_add(self.stats.update, cpu, mem, disk, swap, conns)
            except Exception:
                pass
            time.sleep(2)

    def _journald_loop(self):
        """Stream logs from journald"""
        proc = subprocess.Popen(
            ["journalctl", "-f", "-o", "json", "-p", "notice"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )

        for line in proc.stdout:
            try:
                data = json.loads(line.decode())
                priority = int(data.get("PRIORITY", 6))

                if priority <= 2:
                    severity = Severity.CRITICAL
                elif priority == 3:
                    severity = Severity.HIGH
                elif priority == 4:
                    severity = Severity.MEDIUM
                elif priority == 5:
                    severity = Severity.LOW
                else:
                    severity = Severity.INFO

                event = LogEvent(
                    timestamp=datetime.fromtimestamp(
                        int(data.get("__REALTIME_TIMESTAMP", 0)) / 1_000_000
                    ).isoformat(),
                    source=data.get("_SYSTEMD_UNIT", "system")[:20],
                    message=data.get("MESSAGE", "")[:200],
                    severity=severity
                )

                GLib.idle_add(self.logs_view.add_log, event)

                if severity in (Severity.CRITICAL, Severity.HIGH):
                    GLib.idle_add(self.alerts_view.add_log, event)

            except (json.JSONDecodeError, ValueError):
                continue

    def _suricata_loop(self):
        """Stream Suricata EVE logs"""
        eve_path = Path("/var/log/suricata/eve.json")
        if not eve_path.exists():
            return

        proc = subprocess.Popen(
            ["tail", "-f", "-n", "0", str(eve_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )

        for line in proc.stdout:
            try:
                data = json.loads(line.decode())
                if data.get("event_type") == "alert":
                    alert = data.get("alert", {})
                    severity_map = {1: Severity.CRITICAL, 2: Severity.HIGH, 3: Severity.MEDIUM}
                    severity = severity_map.get(alert.get("severity", 3), Severity.LOW)

                    event = LogEvent(
                        timestamp=data.get("timestamp", ""),
                        source="suricata",
                        message=alert.get("signature", "Unknown alert"),
                        severity=severity,
                        category=alert.get("category", "")
                    )

                    GLib.idle_add(self.alerts_view.add_log, event)
                    GLib.idle_add(self.suricata_view.add_log, event)

            except (json.JSONDecodeError, ValueError):
                continue

    def _on_action(self, action: str):
        """Handle quick action buttons"""
        if action == "clear":
            self.logs_view.clear()
            self.alerts_view.clear()
        elif action == "analyze":
            self.stack.set_visible_child_name("chat")
            self._on_chat_send("Analyze recent security alerts and provide a threat assessment.")
        elif action == "emergency":
            self.stack.set_visible_child_name("chat")
            self._on_chat_send("EMERGENCY: Provide immediate incident response checklist for a potential security breach.")
        elif action == "suricata":
            self.stack.set_visible_child_name("suricata")
        elif action == "status":
            # Show stats
            pass
        elif action == "refresh":
            pass

    def _on_chat_send(self, message: str):
        """Handle chat messages"""
        if not HAS_AIOHTTP:
            self.chat.add_message("System", "aiohttp not available for LLM chat", is_user=False)
            return

        threading.Thread(
            target=self._call_llm,
            args=(message,),
            daemon=True
        ).start()

    def _call_llm(self, prompt: str):
        """Call llama.cpp API in background thread (OpenAI-compatible)"""
        import requests
        import os

        system_prompt = """You are a SOC (Security Operations Center) AI assistant.
You help security analysts understand log events, identify threats, and respond to incidents.
Be concise but thorough. Suggest actionable next steps when relevant."""

        llm_url = os.getenv("LLAMACPP_URL", "http://localhost:8080")

        try:
            response = requests.post(
                f"{llm_url}/v1/chat/completions",
                json={
                    "model": "default",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.7,
                    "max_tokens": 500,
                    "stream": False
                },
                timeout=60
            )

            if response.status_code == 200:
                data = response.json()
                choices = data.get("choices", [])
                if choices:
                    msg = choices[0].get("message", {}).get("content", "No response")
                    GLib.idle_add(self.chat.add_message, "AI", msg, False)
                else:
                    GLib.idle_add(self.chat.add_message, "Error", "No response from LLM", False)
            else:
                GLib.idle_add(self.chat.add_message, "Error", f"API error: {response.status_code}", False)

        except Exception as e:
            GLib.idle_add(self.chat.add_message, "Error", str(e), False)


class SwissMonitorApp(Adw.Application):
    """Main application"""

    def __init__(self):
        super().__init__(
            application_id="com.voidnxsec.swiss-monitor",
            flags=Gio.ApplicationFlags.FLAGS_NONE
        )

    def do_activate(self):
        win = SwissMonitorWindow(self)
        win.present()


def main():
    app = SwissMonitorApp()
    app.run(sys.argv)


if __name__ == "__main__":
    main()
