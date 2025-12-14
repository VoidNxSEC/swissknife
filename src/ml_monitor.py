#!/usr/bin/env python3
"""
Swiss Monitor TUI SOC - Security Operations Center Monitor

A professional terminal UI for real-time security monitoring with:
- Real-time log streaming from journald, Suricata, FIM
- LLM chat for emergency assistance (Ollama)
- Glassmorphism styling for Hyprland
- Keyboard shortcuts and actionable buttons
- Alert severity classification

Run: swiss-monitor
"""

import asyncio
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

import aiohttp
import psutil
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Log,
    Markdown,
    ProgressBar,
    RichLog,
    Rule,
    Static,
    TabbedContent,
    TabPane,
)


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
    raw: dict = field(default_factory=dict)


@dataclass
class SystemStats:
    """System resource statistics"""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    swap_percent: float = 0.0
    network_rx: int = 0
    network_tx: int = 0
    active_connections: int = 0


class StatsPanel(Static):
    """System statistics panel with real-time updates"""

    stats = reactive(SystemStats())

    def compose(self) -> ComposeResult:
        yield Static(id="stats-content")

    def watch_stats(self, stats: SystemStats) -> None:
        content = self.query_one("#stats-content", Static)
        cpu_color = "green" if stats.cpu_percent < 50 else "yellow" if stats.cpu_percent < 80 else "red"
        mem_color = "green" if stats.memory_percent < 60 else "yellow" if stats.memory_percent < 85 else "red"

        text = f"""╭─── System Vitals ───╮
│ CPU:  [{cpu_color}]{stats.cpu_percent:5.1f}%[/]        │
│ RAM:  [{mem_color}]{stats.memory_percent:5.1f}%[/]        │
│ Disk: {stats.disk_percent:5.1f}%         │
│ Swap: {stats.swap_percent:5.1f}%         │
├─── Network ─────────┤
│ RX: {stats.network_rx / 1024 / 1024:6.1f} MB     │
│ TX: {stats.network_tx / 1024 / 1024:6.1f} MB     │
│ Conns: {stats.active_connections:4d}         │
╰─────────────────────╯"""
        content.update(text)


class AlertsPanel(Static):
    """Recent security alerts panel"""

    alerts: reactive[list] = reactive(list)

    def compose(self) -> ComposeResult:
        yield RichLog(id="alerts-log", highlight=True, markup=True, max_lines=100)

    def add_alert(self, event: LogEvent) -> None:
        log = self.query_one("#alerts-log", RichLog)
        time_str = event.timestamp[11:19] if len(event.timestamp) > 11 else event.timestamp
        log.write(
            f"[{event.severity.color}]{event.severity.icon}[/] "
            f"[dim]{time_str}[/] "
            f"[cyan]{event.source}[/] "
            f"{event.message[:80]}"
        )


class ChatPanel(Static):
    """LLM Chat panel for emergency assistance"""

    def compose(self) -> ComposeResult:
        yield Vertical(
            ScrollableContainer(
                RichLog(id="chat-log", highlight=True, markup=True, max_lines=500),
                id="chat-scroll"
            ),
            Horizontal(
                Input(placeholder="Ask about security events...", id="chat-input"),
                Button("Send", id="chat-send", variant="primary"),
                id="chat-controls"
            ),
            id="chat-container"
        )

    async def send_message(self, message: str) -> None:
        chat_log = self.query_one("#chat-log", RichLog)
        chat_log.write(f"[bold cyan]You:[/] {message}")

        # Call Ollama
        try:
            response = await self._call_ollama(message)
            chat_log.write(f"[bold green]AI:[/] {response}")
        except Exception as e:
            chat_log.write(f"[bold red]Error:[/] {str(e)}")

    async def _call_ollama(self, prompt: str) -> str:
        """Call Ollama API for chat response"""
        system_prompt = """You are a SOC (Security Operations Center) AI assistant.
You help security analysts understand log events, identify threats, and respond to incidents.
Be concise but thorough. Suggest actionable next steps when relevant."""

        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://localhost:11434/api/chat",
                json={
                    "model": "llama3.2:3b",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    "stream": False,
                    "options": {"temperature": 0.7, "num_predict": 500}
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("message", {}).get("content", "No response")
                else:
                    return f"API error: {resp.status}"


class LogsPanel(Static):
    """Real-time logs streaming panel"""

    def compose(self) -> ComposeResult:
        yield RichLog(id="logs-stream", highlight=True, markup=True, max_lines=1000)

    def add_log(self, event: LogEvent) -> None:
        log = self.query_one("#logs-stream", RichLog)
        time_str = event.timestamp[11:19] if len(event.timestamp) > 11 else event.timestamp
        log.write(
            f"[dim]{time_str}[/] "
            f"[{event.severity.color}]{event.severity.icon}[/] "
            f"[blue]{event.source}[/] "
            f"{event.message}"
        )


class ActionsPanel(Static):
    """Quick actions panel with buttons"""

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("⚡ Quick Actions", classes="panel-title"),
            Rule(),
            Button("🔍 Analyze Threats", id="btn-analyze", variant="primary"),
            Button("🛡️ Check Suricata", id="btn-suricata"),
            Button("📊 Generate Report", id="btn-report"),
            Button("🔄 Reload Rules", id="btn-reload"),
            Button("⚠️ Test Alert", id="btn-test"),
            Rule(),
            Button("🚨 EMERGENCY", id="btn-emergency", variant="error"),
            id="actions-container"
        )


class SwissMonitorApp(App):
    """Swiss Monitor TUI SOC Application"""

    CSS = """
    /* Glassmorphism-inspired theme for Hyprland */

    Screen {
        background: #0d1117;
    }

    Header {
        background: #161b22;
        color: #58a6ff;
        text-style: bold;
    }

    Footer {
        background: #161b22;
    }

    #main-container {
        layout: grid;
        grid-size: 3 2;
        grid-columns: 1fr 2fr 1fr;
        grid-rows: 1fr 1fr;
        padding: 1;
    }

    #stats-panel {
        row-span: 1;
        border: solid #30363d;
        background: #161b2280;
        padding: 1;
    }

    #alerts-panel {
        column-span: 2;
        border: solid #f85149;
        background: #161b2280;
        padding: 1;
    }

    #logs-panel {
        column-span: 2;
        border: solid #30363d;
        background: #161b2280;
        padding: 1;
    }

    #actions-panel {
        border: solid #238636;
        background: #161b2280;
        padding: 1;
    }

    #chat-panel {
        border: solid #58a6ff;
        background: #161b2280;
        padding: 1;
    }

    .panel-title {
        text-style: bold;
        color: #58a6ff;
    }

    Button {
        margin: 1 0;
        width: 100%;
    }

    #btn-emergency {
        background: #da3633;
        margin-top: 2;
    }

    #chat-container {
        height: 100%;
    }

    #chat-scroll {
        height: 1fr;
        border: solid #30363d;
    }

    #chat-controls {
        height: 3;
        margin-top: 1;
    }

    #chat-input {
        width: 1fr;
    }

    #chat-send {
        width: auto;
    }

    TabbedContent {
        height: 100%;
    }

    TabPane {
        padding: 1;
    }

    RichLog {
        background: #0d111799;
        scrollbar-background: #21262d;
        scrollbar-color: #30363d;
    }
    """

    TITLE = "🇨🇭 Swiss Monitor SOC"
    SUB_TITLE = "Security Operations Center"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("f1", "focus_logs", "Logs"),
        Binding("f2", "focus_alerts", "Alerts"),
        Binding("f3", "focus_chat", "Chat"),
        Binding("f5", "refresh", "Refresh"),
        Binding("f10", "emergency", "EMERGENCY"),
        Binding("ctrl+l", "clear_logs", "Clear"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()

        with TabbedContent():
            with TabPane("📊 Dashboard", id="tab-dashboard"):
                with Container(id="main-container"):
                    yield StatsPanel(id="stats-panel")
                    yield AlertsPanel(id="alerts-panel")
                    yield ActionsPanel(id="actions-panel")
                    yield LogsPanel(id="logs-panel")

            with TabPane("💬 AI Assistant", id="tab-chat"):
                yield ChatPanel(id="chat-panel")

            with TabPane("📈 Suricata", id="tab-suricata"):
                yield RichLog(id="suricata-log", highlight=True, markup=True)

            with TabPane("📁 FIM", id="tab-fim"):
                yield RichLog(id="fim-log", highlight=True, markup=True)

        yield Footer()

    async def on_mount(self) -> None:
        """Start background tasks when app mounts"""
        self.run_worker(self._update_stats(), exclusive=True, name="stats")
        self.run_worker(self._stream_journald(), exclusive=True, name="journald")
        self.run_worker(self._stream_suricata(), exclusive=True, name="suricata")

    @work(exclusive=True)
    async def _update_stats(self) -> None:
        """Update system stats periodically"""
        net_io_start = psutil.net_io_counters()
        while True:
            try:
                net_io = psutil.net_io_counters()
                stats = SystemStats(
                    cpu_percent=psutil.cpu_percent(interval=None),
                    memory_percent=psutil.virtual_memory().percent,
                    disk_percent=psutil.disk_usage('/').percent,
                    swap_percent=psutil.swap_memory().percent,
                    network_rx=net_io.bytes_recv - net_io_start.bytes_recv,
                    network_tx=net_io.bytes_sent - net_io_start.bytes_sent,
                    active_connections=len(psutil.net_connections())
                )
                try:
                    panel = self.query_one("#stats-panel", StatsPanel)
                    panel.stats = stats
                except NoMatches:
                    pass
            except Exception:
                pass
            await asyncio.sleep(2)

    @work(exclusive=True)
    async def _stream_journald(self) -> None:
        """Stream logs from journald"""
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "-f", "-o", "json", "-p", "notice",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )

        while True:
            line = await proc.stdout.readline()
            if not line:
                break

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

                try:
                    logs_panel = self.query_one("#logs-panel", LogsPanel)
                    logs_panel.add_log(event)

                    if severity in (Severity.CRITICAL, Severity.HIGH):
                        alerts_panel = self.query_one("#alerts-panel", AlertsPanel)
                        alerts_panel.add_alert(event)
                except NoMatches:
                    pass

            except (json.JSONDecodeError, ValueError):
                continue

    @work(exclusive=True)
    async def _stream_suricata(self) -> None:
        """Stream Suricata EVE JSON logs"""
        eve_path = Path("/var/log/suricata/eve.json")
        if not eve_path.exists():
            return

        proc = await asyncio.create_subprocess_exec(
            "tail", "-f", "-n", "0", str(eve_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )

        while True:
            line = await proc.stdout.readline()
            if not line:
                break

            try:
                data = json.loads(line.decode())
                event_type = data.get("event_type", "unknown")

                if event_type == "alert":
                    alert = data.get("alert", {})
                    severity_map = {1: Severity.CRITICAL, 2: Severity.HIGH, 3: Severity.MEDIUM}
                    severity = severity_map.get(alert.get("severity", 3), Severity.LOW)

                    event = LogEvent(
                        timestamp=data.get("timestamp", ""),
                        source=f"suricata:{event_type}",
                        message=alert.get("signature", "Unknown alert"),
                        severity=severity,
                        category=alert.get("category", "")
                    )

                    try:
                        alerts_panel = self.query_one("#alerts-panel", AlertsPanel)
                        alerts_panel.add_alert(event)

                        suricata_log = self.query_one("#suricata-log", RichLog)
                        suricata_log.write(
                            f"[{severity.color}]{severity.icon}[/] "
                            f"[dim]{event.timestamp}[/] "
                            f"{event.message}"
                        )
                    except NoMatches:
                        pass

            except (json.JSONDecodeError, ValueError):
                continue

    @on(Button.Pressed, "#chat-send")
    async def handle_chat_send(self) -> None:
        """Handle chat send button"""
        try:
            chat_input = self.query_one("#chat-input", Input)
            message = chat_input.value.strip()
            if message:
                chat_panel = self.query_one("#chat-panel", ChatPanel)
                await chat_panel.send_message(message)
                chat_input.value = ""
        except NoMatches:
            pass

    @on(Input.Submitted, "#chat-input")
    async def handle_chat_submit(self, event: Input.Submitted) -> None:
        """Handle enter key in chat input"""
        await self.handle_chat_send()

    @on(Button.Pressed, "#btn-analyze")
    async def handle_analyze(self) -> None:
        """Analyze recent threats with LLM"""
        try:
            chat_panel = self.query_one("#chat-panel", ChatPanel)
            await chat_panel.send_message(
                "Analyze the recent security alerts and provide a threat assessment summary."
            )
            self.query_one(TabbedContent).active = "tab-chat"
        except NoMatches:
            pass

    @on(Button.Pressed, "#btn-suricata")
    async def handle_suricata_check(self) -> None:
        """Check Suricata status"""
        self.query_one(TabbedContent).active = "tab-suricata"

    @on(Button.Pressed, "#btn-test")
    async def handle_test_alert(self) -> None:
        """Generate a test alert"""
        event = LogEvent(
            timestamp=datetime.now().isoformat(),
            source="test",
            message="🧪 Test alert generated by user",
            severity=Severity.HIGH
        )
        try:
            alerts_panel = self.query_one("#alerts-panel", AlertsPanel)
            alerts_panel.add_alert(event)
        except NoMatches:
            pass

    @on(Button.Pressed, "#btn-emergency")
    async def handle_emergency(self) -> None:
        """Emergency mode"""
        try:
            chat_panel = self.query_one("#chat-panel", ChatPanel)
            await chat_panel.send_message(
                "EMERGENCY: Provide immediate incident response checklist for a potential security breach."
            )
            self.query_one(TabbedContent).active = "tab-chat"
        except NoMatches:
            pass

    def action_focus_logs(self) -> None:
        self.query_one(TabbedContent).active = "tab-dashboard"

    def action_focus_alerts(self) -> None:
        self.query_one(TabbedContent).active = "tab-dashboard"

    def action_focus_chat(self) -> None:
        self.query_one(TabbedContent).active = "tab-chat"

    def action_emergency(self) -> None:
        asyncio.create_task(self.handle_emergency())

    def action_refresh(self) -> None:
        self.refresh()

    def action_clear_logs(self) -> None:
        try:
            self.query_one("#logs-stream", RichLog).clear()
        except NoMatches:
            pass


def main():
    app = SwissMonitorApp()
    app.run()


if __name__ == "__main__":
    main()
