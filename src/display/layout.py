from datetime import datetime
from typing import Iterator, Optional
from src.cve_searcher.cvematch import CVEMatch
from src.cve_searcher.cvequery import CVEQuery
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import track, Progress, SpinnerColumn, BarColumn, TextColumn

NVD_LINK_FORMAT = "https://nvd.nist.gov/vuln/detail/{id}"


class HeaderLayout:
    def __rich__(self) -> Panel:
        table = Table.grid(padding=1)
        table.add_column(justify="right", ratio=1)
        table.add_row(Text(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style="gray"))
        return Panel(
            table,
            title="[bold]YACS - Yet Another CVE Searcher",
            subtitle="Thank you for using me !",
            style="bold",
        )


class QueryLayout:
    def __init__(self, query: CVEQuery) -> None:
        self.query = query

    def __rich__(self) -> Panel:
        values = [
            (Text("Vendor", style="bold magenta"), self.query.vendor),
            (Text("Raw Product", style="bold red"), self.query._product),
            (Text("Version", style="bold blue"), self.query.version),
            (Text("Normalized Product", style="bold green"), self.query.product),
        ]
        table = Table.grid(padding=1)
        table.add_column(justify="left", ratio=1)
        table.add_column(justify="left")
        for key, value in values:
            table.add_row(key, ":", Text(str(value), style="white"))
        table_panel = Panel.fit(table, title="[bold]Query", style="bold blue")
        return table_panel


class MatchesLayout:
    def __init__(self, matches: Optional[Iterator[CVEMatch]]) -> None:
        self.matches_iter = matches
        self.matches = []
        self.loaded = False
        self.job_progress = Progress(
            "{task.description}",
            SpinnerColumn(),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        )
        self.loading_id = self.job_progress.add_task(
            description="Loading matches...", start=True
        )

    def generate_row(self, match: CVEMatch) -> list[Text]:
        return [
            Text(match.cve["cve"]["CVE_data_meta"]["ID"], style="bold"),
            Text(str(match.confidence_score), style="bold green"),
            Text(str(len(match.cve["references"]["reference"]), style="bold blue")),
            Text(str(match.confidence_score), style="bold red"),
            Text(
                f"[u link={NVD_LINK_FORMAT.format(id=match.cve['cve']['CVE_data_meta']['ID'])}]",
                style="bold cyan",
            ),
        ]

    def __rich__(self) -> Panel:
        if self.matches_iter is None:
            return Panel(
                Text("No matches found"), title="[bold]Matches", style="bold red"
            )

        if not self.loaded:
            try:
                self.matches.append(next(self.matches_iter))
                self.job_progress.advance(self.loading_id)

            except StopIteration:
                self.loaded = True
                self.job_progress.remove_task(self.loading_id)
                self.job_progress.stop()
            finally:
                return Panel(self.job_progress)

        table = Table.grid("ID", "Score", "No.", "Confidence", "Link", padding=1)
        for match in self.matches:
            table.add_row(*self.generate_row(match))

        panel = Panel(table, title="[bold]Matches", style="bold green")
        panel = Panel("hello world loaded", title="[bold]Matches", style="bold green")
        
        return panel


def base_layout() -> Layout:
    layout = Layout(name="root")
    main_layout = Layout(name="main")
    main_layout.split_row(
        Layout(Panel(""), name="query"), Layout(MatchesLayout(None), name="matches")
    )
    layout.split(
        Layout(HeaderLayout(), name="header", size=3),
        main_layout,
        Layout(name="footer", size=7),
    )

    return layout
