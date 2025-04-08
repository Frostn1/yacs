import readline
from typing import Callable, Optional
from interactive.utils import fetch_products, fetch_vendors
from loguru import logger
from rich.prompt import Prompt, Confirm
from rich import print as rich_print
from rich.panel import Panel
from rich.tree import Tree
from rich.console import Console
from rich.layout import Layout
from rich import print


def is_familier(choice: str, options: list[str]) -> Optional[str]:
    for option in options:
        if choice.lower() in option.lower():
            return option
    return None


def completer_wrapper(
    func: Callable[[str, int, list[str]], Optional[str]], options: list[str]
) -> Callable[[str, int], Optional[str]]:
    def wrapped(prefix: str, index: int) -> Optional[str]:
        return func(prefix, index, options)

    return wrapped


def complete_with_options(prefix: str, index: int, options: list[str]) -> Optional[str]:
    matches = [
        option for option in options if option.lower().startswith(prefix.lower())
    ]
    return matches[index] if index < len(matches) else None


def test_display(
    substitution: str, matches: list[str], longest_match_length: int
) -> None:
    print(f"{substitution = } {matches = } {longest_match_length = }")


def loop(*_) -> None:
    # vendors = fetch_vendors()
    # products = fetch_products()
    # vendor = Prompt.ask("Enter vendor name", default=None)
    layout = Layout()
    layout.split_column(Layout(name="upper"), Layout(name="lower"))
    layout["lower"].split_row(
        Layout(name="left"),
        Layout(name="right"),
    )
    layout["right"].split(Layout(Panel("Hello")), Layout(Panel("World!")))
    # print(layout)
    layout["left"].update(
        "The mystery of life isn't a problem to solve, but a reality to experience."
    )
    # print(layout)
    from time import sleep

    from rich.live import Live

    with Live(layout, refresh_per_second=10, screen=True):
        sleep(10)
    # readline.set_completer(completer_wrapper(complete_with_options, fetch_vendors()))
    # # readline.set_completion_display_matches_hook(test_display)
    # readline.parse_and_bind("tab: complete")
    # input("hello world: ")
    # logger.info("Interactive mode")
