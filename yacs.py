#!/usr/bin/python


import argparse
import sys

from cve_searcher.cvequery import CVEQuery
from cve_searcher.search_vulnerabilties import search_vulnerabilities
from loguru import logger
from mongodb import MongoDBClient

from src.nvd.mirror_nvd import NVD_MAX_YEAR, NVD_MIN_YEAR, setup_db
from packaging.version import Version
from interactive.interactive import loop as interactive_loop
from rich.console import Console

console = Console(color_system=None, stderr=True)


SEARCH_COMMAND = "search"
MIRROR_COMMAND = "mirror"
INTERACTIVE_COMMAND = "interactive"


def search(args: argparse.Namespace) -> None:
    with MongoDBClient() as mdb_client:
        cve_collection = mdb_client.nvd_mirror.cves
        query = CVEQuery(
            args.vendor,
            args.product,
            Version(args.version),
            not args.dont_normalize_product,
        )
        cves = search_vulnerabilities(cve_collection, query)
        count: int = -1
        for count, cvematch in enumerate(cves):
            logger.info(
                f"Found CVE [Confidence {cvematch.score}] - {query.version} {cvematch.cve['cve']['CVE_data_meta']['ID']}"
            )
        print(f"Query - {query} {query.product} , Found {count + 1} cves")


def mirror(_: argparse.Namespace) -> None:
    with MongoDBClient() as mdb_client:
        cve_collection = mdb_client.nvd_mirror.cves
        meta_collection = mdb_client.nvd_mirror.meta
        setup_db(cve_collection, meta_collection)


ACTIONS = {
    SEARCH_COMMAND: search,
    MIRROR_COMMAND: mirror,
    INTERACTIVE_COMMAND: interactive_loop,
}


def main() -> None:
    parser = argparse.ArgumentParser("yacs", description="Yet Another CVE Searcher")
    subparsers = parser.add_subparsers(dest="command")
    mirror_parser = subparsers.add_parser(MIRROR_COMMAND, help="Mirror NVD to MongoDB")
    mirror_parser.add_argument(
        "--year-start",
        help="Start year range for mirror",
        default=NVD_MIN_YEAR,
        type=int,
    )
    mirror_parser.add_argument(
        "--year-end", help="End year range for mirror", default=NVD_MAX_YEAR, type=int
    )

    search_parser = subparsers.add_parser(
        SEARCH_COMMAND, help="Search CVE in MongoDB mirror"
    )
    search_parser.add_argument("product", help="Proudct parameter", default="")
    search_parser.add_argument("--vendor", help="Vendor parameter", default="")
    search_parser.add_argument("--version", help="Version parameter", default="0")
    search_parser.add_argument(
        "--dont-normalize-product",
        help="Don't normalize product name when searching",
        action="store_true",
        default=False,
    )
    # _ = subparsers.add_parser(
    #     INTERACTIVE_COMMAND, help="Interactive mode using rich"
    # )
    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        exit(0)

    ACTIONS.get(args.command)(args)


if __name__ == "__main__":
    logger.remove()
    logger.add(lambda m: console.print(m, end=""), colorize=True, level="INFO")
    main()
