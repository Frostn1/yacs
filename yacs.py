#!/usr/bin/python
import argparse
import sys

from loguru import logger

from src.cvequery import CVEQuery
from src.mdb_client import MongoDBClient, UpdateOperation
from src.mirror_nvd import NVD_MAX_YEAR, NVD_MIN_YEAR, update_checkpoints, update_cves
from packaging.version import Version

from src.search_vulnerabilties import search_vulnerabilities

SEARCH_COMMAND = "search"
MIRROR_COMMAND = "mirror"


def search(args: argparse.Namespace) -> None:
    with MongoDBClient() as mdb_client:
        cve_collection = mdb_client["nvd_mirror"]["cves"]
        query = CVEQuery(
            args.vendor,
            args.product,
            Version(args.version),
            args.dont_normalize_product,
        )
        _, cves = search_vulnerabilities(cve_collection, query)
        cves = list(cves)
        print(f"Query - {query} , Found {len(cves)} cves")
        input()
        for cvematch in cves:
            logger.info(
                f"Found CVE [Confidence {cvematch.get_raw_confidences}] - {query.version} {cvematch.cve['cve']['CVE_data_meta']['ID']}"
            )


def mirror(args: argparse.Namespace) -> None:
    with MongoDBClient() as mdb_client:
        cve_collection = mdb_client["nvd_mirror"]["cves"]
        meta_collection = mdb_client["nvd_mirror"]["meta"]
        update_cves(
            cve_collection=cve_collection,
            meta_collection=meta_collection,
            operation=UpdateOperation.INITIAL if args.initial else UpdateOperation.SYNC,
        )
        update_checkpoints(
            meta_collection=meta_collection,
            min_year=args.year_start,
            max_year=args.year_end,
        )


ACTIONS = {SEARCH_COMMAND: search, MIRROR_COMMAND: mirror}


def main() -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO")

    parser = argparse.ArgumentParser("yacs", description="Yet Another CVE Searcher")
    subparsers = parser.add_subparsers(dest="command")
    mirror_parser = subparsers.add_parser(MIRROR_COMMAND, help="Mirror NVD to MongoDB")
    mirror_parser.add_argument("-s", "--sync", help="Sync running mirror with NVD.", action="store_true")
    mirror_parser.add_argument(
        "-i", "--initial", help="Inital mirror install from NVD to MongoDB", action="store_true"
    )
    mirror_parser.add_argument(
        "--year-start", help="Start year range for mirror", default=NVD_MIN_YEAR
    )
    mirror_parser.add_argument(
        "--year-end", help="End year range for mirror", default=NVD_MAX_YEAR
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
        default=True,
    )
    search_parser.add_argument(
        "--file",
        help="File coherting to README' described structure.\nOverrides cmdline parameters",
    )
    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        exit(0)
    print(args)
    ACTIONS.get(args.command)(args)


if __name__ == "__main__":
    main()
