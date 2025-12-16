#!/usr/bin/env python3
"""
Swiss Monitor Systray - Wayland System Tray Indicator

A GTK4/libappindicator-based systray that:
- Shows red alert icon when critical events detected
- Shows green icon when system is healthy
- Connects to the TUI SOC via D-Bus
- Click to open TUI monitor

Works with Hyprland/Waybar via StatusNotifierItem protocol.
"""

import warnings

# Suppress annoying deprecation warnings from AppIndicator3
warnings.filterwarnings("ignore", category=DeprecationWarning)

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('AppIndicator3', '0.1')

import asyncio
import json
import os
import signal
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

from gi.repository import AppIndicator3, GLib, Gtk


class SwissSystray:
    """Swiss Monitor System Tray Indicator"""

    ICON_NORMAL = "security-high-symbolic"
    ICON_WARNING = "dialog-warning-symbolic"
    ICON_CRITICAL = "dialog-error-symbolic"

    # Custom icon paths for glassmorphism theme
    ICONS_DIR = Path(__file__).parent / "icons"

    def __init__(self):
        self.indicator = AppIndicator3.Indicator.new(
            "swiss-monitor",
            self.ICON_NORMAL,
            AppIndicator3.IndicatorCategory.SYSTEM_SERVICES
        )
        self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.indicator.set_title("Swiss Monitor SOC")

        # Create menu
        self.menu = Gtk.Menu()
        self._build_menu()
        self.indicator.set_menu(self.menu)

        # Alert state
        self.alert_level = "normal"  # normal, warning, critical
        self.alert_count = 0
        self.last_alert = None

        # Start alert monitoring thread
        self._start_alert_monitor()

    def _build_menu(self):
        """Build the systray menu"""
        # Status item (updated dynamically)
        self.status_item = Gtk.MenuItem(label="🟢 System Normal")
        self.status_item.set_sensitive(False)
        self.menu.append(self.status_item)

        self.menu.append(Gtk.SeparatorMenuItem())

        # Open TUI Monitor
        item_open = Gtk.MenuItem(label="📊 Open SOC Monitor")
        item_open.connect("activate", self._on_open_monitor)
        self.menu.append(item_open)

        # Quick actions
        item_doctor = Gtk.MenuItem(label="🩺 Run System Doctor")
        item_doctor.connect("activate", self._on_run_doctor)
        self.menu.append(item_doctor)

        item_logs = Gtk.MenuItem(label="📜 View Recent Logs")
        item_logs.connect("activate", self._on_view_logs)
        self.menu.append(item_logs)

        self.menu.append(Gtk.SeparatorMenuItem())

        # Alert counter
        self.alert_item = Gtk.MenuItem(label="⚡ Alerts: 0")
        self.alert_item.set_sensitive(False)
        self.menu.append(self.alert_item)

        # Clear alerts
        item_clear = Gtk.MenuItem(label="🧹 Clear Alerts")
        item_clear.connect("activate", self._on_clear_alerts)
        self.menu.append(item_clear)

        self.menu.append(Gtk.SeparatorMenuItem())

        # Quit
        item_quit = Gtk.MenuItem(label="❌ Quit")
        item_quit.connect("activate", self._on_quit)
        self.menu.append(item_quit)

        self.menu.show_all()

    def _on_open_monitor(self, widget):
        """Open the TUI SOC Monitor"""
        # Launch in a new terminal (works with foot, alacritty, etc.)
        terminals = [
            ["foot", "-e", "swiss-monitor"],
            ["alacritty", "-e", "swiss-monitor"],
            ["kitty", "swiss-monitor"],
            ["gnome-terminal", "--", "swiss-monitor"],
        ]

        for terminal_cmd in terminals:
            try:
                subprocess.Popen(terminal_cmd, start_new_session=True)
                return
            except FileNotFoundError:
                continue

        # Fallback: just try to run directly
        subprocess.Popen(["swiss-monitor"], start_new_session=True)

    def _on_run_doctor(self, widget):
        """Run system doctor"""
        terminals = [
            ["foot", "-e", "swiss-doctor"],
            ["alacritty", "-e", "swiss-doctor"],
        ]

        for terminal_cmd in terminals:
            try:
                subprocess.Popen(terminal_cmd, start_new_session=True)
                return
            except FileNotFoundError:
                continue

    def _on_view_logs(self, widget):
        """View recent logs in terminal"""
        cmd = ["foot", "-e", "journalctl", "-f", "-p", "notice"]
        try:
            subprocess.Popen(cmd, start_new_session=True)
        except FileNotFoundError:
            pass

    def _on_clear_alerts(self, widget):
        """Clear alert counter"""
        self.alert_count = 0
        self.alert_level = "normal"
        self._update_icon()
        GLib.idle_add(self._update_menu)

    def _on_quit(self, widget):
        """Quit the systray"""
        Gtk.main_quit()

    def _update_icon(self):
        """Update the systray icon based on alert level"""
        if self.alert_level == "critical":
            self.indicator.set_icon(self.ICON_CRITICAL)
            self.indicator.set_attention_icon(self.ICON_CRITICAL)
            self.indicator.set_status(AppIndicator3.IndicatorStatus.ATTENTION)
        elif self.alert_level == "warning":
            self.indicator.set_icon(self.ICON_WARNING)
            self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        else:
            self.indicator.set_icon(self.ICON_NORMAL)
            self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)

    def _update_menu(self):
        """Update menu items"""
        if self.alert_level == "critical":
            self.status_item.set_label("🔴 CRITICAL ALERT!")
        elif self.alert_level == "warning":
            self.status_item.set_label("🟡 Warning")
        else:
            self.status_item.set_label("🟢 System Normal")

        self.alert_item.set_label(f"⚡ Alerts: {self.alert_count}")

    def _start_alert_monitor(self):
        """Start background thread to monitor for alerts"""
        thread = threading.Thread(target=self._monitor_alerts, daemon=True)
        thread.start()

    def _monitor_alerts(self):
        """Monitor journald for security alerts"""
        try:
            proc = subprocess.Popen(
                ["journalctl", "-f", "-o", "json", "-p", "warning"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )

            for line in proc.stdout:
                try:
                    data = json.loads(line.decode())
                    priority = int(data.get("PRIORITY", 6))
                    message = data.get("MESSAGE", "")

                    # Check for security-related keywords
                    security_keywords = [
                        "suricata", "security", "alert", "attack",
                        "unauthorized", "denied", "failed", "error",
                        "ssh", "audit", "firewall", "intrusion"
                    ]

                    is_security_event = any(
                        kw in message.lower() for kw in security_keywords
                    )

                    if is_security_event or priority <= 3:
                        self.alert_count += 1
                        self.last_alert = message[:100]

                        if priority <= 2:
                            self.alert_level = "critical"
                        elif priority <= 4:
                            if self.alert_level != "critical":
                                self.alert_level = "warning"

                        GLib.idle_add(self._update_icon)
                        GLib.idle_add(self._update_menu)

                        # Show notification for critical alerts
                        if priority <= 2:
                            GLib.idle_add(
                                self._show_notification,
                                "🚨 Security Alert",
                                message[:100]
                            )

                except (json.JSONDecodeError, ValueError):
                    continue

        except Exception as e:
            print(f"Alert monitor error: {e}", file=sys.stderr)

    def _show_notification(self, title: str, body: str):
        """Show desktop notification"""
        try:
            subprocess.run([
                "notify-send",
                "--urgency=critical",
                "--app-name=Swiss Monitor",
                "--icon=dialog-error",
                title,
                body
            ], check=False)
        except FileNotFoundError:
            pass

    def run(self):
        """Run the systray main loop"""
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        Gtk.main()


def main():
    print("🇨🇭 Swiss Monitor Systray starting...")
    print("Icon will appear in your system tray (Waybar, etc.)")

    systray = SwissSystray()
    systray.run()


if __name__ == "__main__":
    main()
