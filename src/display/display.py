from src.yacs_search import YACSSearch
from src.display.layout import MatchesLayout, QueryLayout, base_layout
from rich.live import Live


def display_search(search: YACSSearch) -> None:
    layout = base_layout()
    layout["main"]["query"].update(QueryLayout(search.query))
    layout["main"]["matches"].update(MatchesLayout(search.matches))
    with Live(layout, refresh_per_second=10, screen=True):
        
        input("Enter to quit")
