import time
import os
import sys
import json
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich import box
from monitor import MultiLogMonitor
from storage import get_top_attackers, get_recent_incidents

console = Console()

def load_config():
    with open("config.json", "r") as f:
        return json.load(f)

class IDSDashboard:
    def __init__(self):
        self.config = load_config()
        self.incidents = deque(maxlen=15)
        self.total_processed = 0
        self.total_attacks = 0
        self.start_time = time.time()

    def on_event(self, data):
        self.total_processed += 1
        if data['is_attack']:
            self.total_attacks += 1
            self.incidents.append(data)

    def make_header_panel(self):
        uptime = int(time.time() - self.start_time)
        metrics = (
            f"[bold cyan]UPTIME:[/] {uptime}s | "
            f"[bold green]EVENTS:[/] {self.total_processed} | "
            f"[bold red]ATTACKS:[/] {self.total_attacks} | "
            f"[bold blue]HOST:[/] {os.uname().nodename}"
        )
        return Panel(metrics, style="bold white on blue", box=box.ROUNDED)

    def make_attackers_table(self):
        top = get_top_attackers(5)
        table = Table(title="[bold red]TOP THREAT AGENTS[/]", box=box.SIMPLE_HEAD)
        table.add_column("IP Address", style="cyan")
        table.add_column("Incidents", style="magenta", justify="right")
        
        for ip, count in top:
            table.add_row(ip, str(count))
        return table

    def make_log_table(self):
        table = Table(title="[bold yellow]REAL-TIME INCIDENT RESPONSE LOG[/]", box=box.ROUNDED, expand=True)
        table.add_column("Time", style="dim", width=10)
        table.add_column("Source", style="blue", width=15)
        table.add_column("Stage", style="bold red", width=15)
        table.add_column("Conf/Stat", justify="center", width=12)
        table.add_column("Signature Snippet", overflow="ellipsis")

        for inc in reversed(self.incidents):
            ts = time.strftime('%H:%M:%S', time.localtime(inc['timestamp']))
            conf = inc['confidence'] * 100
            status = "[bold white on red] BLOCKED [/]" if inc['blocked'] else f"{conf:>6.1f}%"
            stage = inc['stage'].upper().replace("_", " ")
            
            table.add_row(
                ts, 
                os.path.basename(inc['source']),
                stage,
                status,
                inc['raw'][:80]
            )
        return table

    def generate_layout(self):
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body")
        )
        layout["body"].split_row(
            Layout(name="main", ratio=3),
            Layout(name="side", ratio=1)
        )
        
        layout["header"].update(self.make_header_panel())
        layout["main"].update(self.make_log_table())
        layout["side"].update(self.make_attackers_table())
        return layout

def main():
    dashboard = IDSDashboard()
    monitor = MultiLogMonitor(dashboard.config, dashboard.on_event)
    monitor.start()

    with Live(dashboard.generate_layout(), refresh_per_second=2) as live:
        try:
            while True:
                time.sleep(0.5)
                live.update(dashboard.generate_layout())
        except KeyboardInterrupt:
            monitor.stop()

if __name__ == "__main__":
    from collections import deque
    main()
