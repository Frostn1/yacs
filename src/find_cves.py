#!/usr/bin/python
from typing import Iterable
from loguru import logger
from pymongo.collection import Collection
from src.utils import greater_version, normalize_app_name


import pymongo
import logging
import argparse
from os import environ as env
import json
import re



# Finds all CVEs that reference this CPE
# BULK VERSION: def find_all_cves(conn, application, versions, debug=False):
def find_cves(cves_collection: Collection, app_name: str, versions: list[str]):
    normalized_app_name = normalize_app_name(app_name)
    # First, we get all CVEs that reference this application
    query = {
        "cve.description.description_data": {
            "$elemMatch": {
                "value": {
                    "$regex": f"(\s|^){normalized_app_name}(\s|$)",
                    "$options": "si",
                }
            }
        }
    }

    logger.debug(f"Application to look up: {app_name}")
    logger.debug(f"Query: {json.dumps(query)}")

    def is_app_in_cpe_uri(normalized_app, uri):
        pattern = r"\W+"
        split_app = re.split(pattern, normalized_app)

        application_part_of_uri = ":".join(uri.split(":")[3:5])
        for x in split_app:
            if x not in application_part_of_uri:
                return False
        return True

    def is_valid_cve(application, version, cve_id, description, cpe_match):
        logger.debug("-----")
        # `confidences` is the output
        confidences = dict()

        # This is what we initially regex for so this must be true
        logger.debug(f"[{cve_id}] - Summary contains application name. +confidence")
        confidences["summary contains app name"] = True

        # This is another validity metric which asks if the CPE URI helps us determine the version validity
        if cpe_match["vulnerable"]:
            cpe_uri = cpe_match["cpe23Uri"]
            if is_app_in_cpe_uri(normalized_app_name, cpe_uri):
                # This is a validity metric where we simply look for the application in the CPE URI as a string
                logger.debug(f"[{cve_id}] - Application in CPE URI. +confidence")
                confidences["app in cpe_uri"] = True
                if cpe_uri.split(":")[5] != "*":
                    version_start = cpe_uri.split(":")[5]
                    version_end = cpe_uri.split(":")[5]
                    if version_start == "-":
                        version_start = 0
                    if version_end == "-":
                        version_end = 9999999999999
                else:
                    try:
                        version_start_including = cpe_match["versionStartIncluding"]
                    except KeyError:
                        version_start_including = None
                    try:
                        version_end_including = cpe_match["versionEndIncluding"]
                    except KeyError:
                        version_end_including = None
                    try:
                        version_start_excluding = cpe_match["versionStartExcluding"]
                    except KeyError:
                        version_start_excluding = None
                    try:
                        version_end_excluding = cpe_match["versionEndExcluding"]
                    except KeyError:
                        version_end_excluding = None

                    if version_start_including is None:
                        if version_start_excluding is None:
                            version_start = 0
                        else:
                            version_start = version_start_excluding
                    else:
                        version_start = version_start_including
                    if version_end_including is None:
                        if version_end_excluding is None:
                            version_end = 999999999999
                        else:
                            version_end = version_end_excluding
                    else:
                        version_end = version_end_including
                greater_start_version = greater_version(
                    str(version), str(version_start)
                )
                greater_end_version = greater_version(str(version), str(version_end))

                if str(greater_start_version) == str(version) and str(
                    greater_end_version
                ) == str(version_end):
                    logger.debug(
                        f"[{cve_id}] - Evaluated CPE: {version_start} <= {version} <= {version_end}. +confidence"
                    )
                    confidences["cpe_version_eval"] = True
                elif "cpe_version_eval" not in confidences.keys():
                    logger.debug(
                        f"[{cve_id}] - Evaluated CPE _INVALID_: {version_start} <= {version} <= {version_end}. -confidence"
                    )
                    confidences["cpe_version_eval"] = False

        # This metric uses regex to go through the summary of the CVE and checks for the version validity that way
        regexes = {
            # Between versions
            "((v?\d\S*?)(\sthrough\s)(v?\d\S*?)(\s|$))|((version|versions)\s(v?\d\S*?)\s(and|to|through)\s(v?\d\S*?)(\s|$))|(between\s(version\s|versions\s)?(v?\d\S*?)\s(and|to|through)\s(v?\d\S*?)(\s|$))|(before\s(version\s|versions\s)?(v?\d\S*?)\s(and\s)?after\s(version\s|versions\s)?(v?\d\S*?)(\s|$))|(after\s(version\s|versions\s)?(v?\d\S*?)\s(and\s)?before\s(version\s|versions\s)?(v?\d\S*?)(\s|$))": "between",
            # Before versions
            "(((versions\s)?(?!v?\d\S*?)(prior(\sto)?|before|below|through)\s(versions\s)?)(v?\d\S*?)(,(\s(and\s)?(v?\d\S*))+))|((((version\s|versions\s)?(?!v?\d\S*?)(prior(\sto)?|before|below|through)\s(version\s|versions\s)?)|(<(=)?\s+?))(v?\d\S*?)(\s|$)(?!and\safter))|(version|versions)?(\s(v?\d\S*?)\s(\()?and\s(below|prior|before|earlier)(\))?)": "before",
            # After versions
            "(?!and)\s((((after)\s(version\s|versions\s)?)|(>(=)?\s+?))(v?\d\S*?)(\s|$)(?!and))|(\s(v?\d\S?)\s(\()and\s(after|later)(\)))": "after",
            # Raw versions
            "(\s(version\s)?(v?\d\S*?)(\s|$)(?!and))": "raw",
        }
        version_re = "v?\d\S*"
        need_raw = True
        regex_found = False
        found_regexes = list()
        for regex in regexes.keys():
            if not regex_found:
                descr_re_result = re.findall(regex, description, flags=re.I | re.M)
                if descr_re_result:
                    if regexes[regex] == "raw":
                        if need_raw:
                            pass
                        else:
                            continue
                    regex_hit_type = regexes[regex].upper()
                    for result in descr_re_result:
                        versions_in_result = set()
                        # Search through the items in the groups
                        if not regex_found:
                            for r in result:
                                if r:
                                    regex_subsearch = re.search(
                                        version_re, r, flags=re.I | re.M
                                    )
                                    if regex_subsearch:
                                        if (
                                            regex_subsearch.group()[-1]
                                            in "!\"#$%&'()*+, -./:;<=>?@[\]^_`{|}~"
                                        ):
                                            subsearch_results = regex_subsearch.group()[
                                                :-1
                                            ].strip()
                                        else:
                                            subsearch_results = (
                                                regex_subsearch.group().strip()
                                            )
                                        if subsearch_results.startswith("v"):
                                            subsearch_results = subsearch_results[1:]
                                        versions_in_result.add(subsearch_results)
                                        need_raw = False
                            versions_in_result = list(versions_in_result)
                            if regex_hit_type == "BETWEEN":
                                # If there's only 1 "version in result" for a "between" hit, we will use it as a regular raw
                                if len(versions_in_result) == 1:
                                    versions_in_result = [versions_in_result[0]] * 2
                                found_regexes.append("BETWEEN")
                                version_end = greater_version(
                                    versions_in_result[0], versions_in_result[1]
                                )
                                if version_end == versions_in_result[0]:
                                    version_start = versions_in_result[1]
                                else:
                                    version_start = versions_in_result[0]
                                if (
                                    greater_version(version_start, version) == version
                                    and greater_version(version_end, version)
                                    == version_end
                                ):
                                    logger.debug(
                                        f"[{cve_id}] - Summary regex evaluation ({regex_hit_type}): {version_start} <= {version} <= {version_end}. +confidence"
                                    )
                                    confidences["summary regex eval"] = True
                                    regex_found = True
                                else:
                                    logger.debug(
                                        f"[{cve_id}] - Summary regex evaluation _INVALID_ ({regex_hit_type}): {version_start} <= {version} <= {version_end}"
                                    )
                            if regex_hit_type == "BEFORE":
                                found_regexes.append("BEFORE")
                                for version_in_result in versions_in_result:
                                    if (
                                        greater_version(version_in_result, version)
                                        == version_in_result
                                    ):
                                        logger.debug(
                                            f"[{cve_id}] - Summary regex evaluation ({regex_hit_type}): {version} < {version_in_result}. +confidence"
                                        )
                                        confidences["summary regex eval"] = True
                                        regex_found = True
                                    else:
                                        logger.debug(
                                            f"[{cve_id}] - Summary regex evaluation _INVALID_ ({regex_hit_type}): {version} < {version_in_result}"
                                        )
                            if regex_hit_type == "AFTER":
                                found_regexes.append("AFTER")
                                for version_in_result in versions_in_result:
                                    if (
                                        greater_version(version_in_result, version)
                                        == version
                                    ):
                                        logger.debug(
                                            f"[{cve_id}] - Summary regex evaluation ({regex_hit_type}): {version_in_result} < {version}. +confidence"
                                        )
                                        confidences["summary regex eval"] = True
                                        regex_found = True
                                    else:
                                        logger.debug(
                                            f"[{cve_id}] - Summary regex evaluation _INVALID_ ({regex_hit_type}): {version_in_result} < {version}"
                                        )
                            if regex_hit_type == "RAW" and need_raw:
                                found_regexes.append("RAW_VERSION")
                                for version_in_result in versions_in_result:
                                    if version_in_result == version:
                                        logger.debug(
                                            f"[{cve_id}] - Summary regex evaluation ({regex_hit_type}): {version_in_result} == {version}. +confidence"
                                        )
                                        confidences["summary regex eval"] = True
                                        regex_found = True
                                    else:
                                        logger.debug(
                                            f"[{cve_id}] - Summary regex evaluation _INVALID_ ({regex_hit_type}): {version_in_result} == {version}"
                                        )

        try:
            confidences["summary regex eval"]
        except KeyError:
            logger.debug(
                f"[{cve_id}] - Summary regex evaluation did not get a verison match (found regexes: {', '.join(found_regexes)}). -confidence"
            )
            confidences["summary regex eval"] = False
        try:
            confidences["app in cpe_uri"]
        except KeyError:
            logger.debug(f"[{cve_id}] - Application not in CPE URI. -confidence")
            confidences["app in cpe_uri"] = False
        try:
            confidences["cpe_version_eval"]
        except KeyError:
            logger.debug(
                f"[{cve_id}] - Did not do CPE version evaluation due to invulnerable CPE or application not in CPE URI. -confidence"
            )
            confidences["app in cpe_uri"] = False

        # Turn confidence dictionary into confidence score (out of 100)
        confidence = (
            (list(confidences.values()).count(True)) / len(list(confidences.values()))
        ) * 100
        logger.debug(
            f"Confidence for {cve_id}: {confidence} - {json.dumps(confidences)}"
        )
        # Threshold for returning True
        if confidence >= 75:
            return True
        else:
            return False

    # TODO - do bulk version of this
    valid_cves = dict()

    def gen_valid_cves(cves, versions):
        logger.info(f"Evaluating {app_name} with version(s) {', '.join(versions)}")
        for version in versions:
            valid_cves[version] = dict()
        for cve in cves:
            nodes = cve["configurations"]["nodes"]
            logger.debug(
                f"------------ [{cve['cve']['CVE_data_meta']['ID']}] -------------"
            )
            logger.debug(
                f"Description: {cve['cve']['description']['description_data'][0]['value']}"
            )
            for version in versions:
                logger.debug(f"Evaluating {app_name} CVEs for version {version}")
                for node in nodes:
                    for child in node["children"]:
                        cpe_matches = child["cpe_match"]
                        for cpe_match in cpe_matches:
                            if (
                                cve["cve"]["CVE_data_meta"]["ID"]
                                not in valid_cves.keys()
                            ):
                                logger.debug(f"CPE: {cpe_match}")
                                if is_valid_cve(
                                    app_name,
                                    version,
                                    cve["cve"]["CVE_data_meta"]["ID"],
                                    cve["cve"]["description"]["description_data"][0][
                                        "value"
                                    ],
                                    cpe_match,
                                ):
                                    logger.info(
                                        f"Valid CVE for {app_name} {version}: {cve['cve']['CVE_data_meta']['ID']}"
                                    )
                                    valid_cves[version][
                                        cve["cve"]["CVE_data_meta"]["ID"]
                                    ] = cve
                                    break
                                else:
                                    logger.debug(
                                        f"Invalid CVE: {cve['cve']['CVE_data_meta']['ID']}"
                                    )

                    cpe_matches = node["cpe_match"]
                    for cpe_match in cpe_matches:
                        if cve["cve"]["CVE_data_meta"]["ID"] not in valid_cves.keys():
                            logger.debug(f"CPE: {cpe_match}")
                            if is_valid_cve(
                                app_name,
                                version,
                                cve["cve"]["CVE_data_meta"]["ID"],
                                cve["cve"]["description"]["description_data"][0][
                                    "value"
                                ],
                                cpe_match,
                            ):
                                logger.info(
                                    f"Valid CVE for {app_name} {version}: {cve['cve']['CVE_data_meta']['ID']}"
                                )
                                valid_cves[version][
                                    cve["cve"]["CVE_data_meta"]["ID"]
                                ] = cve
                                break
                            else:
                                logger.debug(
                                    f"Invalid CVE: {cve['cve']['CVE_data_meta']['ID']}"
                                )

    cve_count = cves_collection.count_documents(query)
    logger.debug(f"MongoDB returned {cve_count} documents for the query")
    # Load the CVEs into a list so we don't have to use a cursor due to 10 minute timeouts
    cves = [_ for _ in cves_collection.find(query)]
    gen_valid_cves(cves, versions)
    return valid_cves


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bulk-file",
        help="A JSON file containing application names and versions you want to look up in bulk",
    )
    parser.add_argument(
        "-a", "--application", help="Application name (case insensitive)"
    )
    parser.add_argument("-v", "--version", help="Version of the application")
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug logs (same as --verbose)"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable debug logs (same as --debug)"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Summarize CVE severities at the end instead of listing every one",
    )
    parser.add_argument("-o", "--output-file", help="Name of the output file")
    parser.add_argument(
        "--no-output-file",
        action="store_true",
        help="Flag to not create an output file",
    )
    parser.add_argument(
        "--silent", action="store_true", help="Only output 'ERROR' (or higher) logs"
    )
    args = parser.parse_args()

    if args.silent:
        logger.setLevel(logging.ERROR)
    if args.debug or args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.debug("Debug/Verbose mode: ON")
    # Set up required arguments
    if not args.bulk_file:
        if args.application:
            if not args.version:
                logger.error("-a/--application requires -v/--version")
                exit(1)
        elif args.version:
            if not args.application:
                logger.error("-v/--version requires -a/--application")
                exit(1)
        else:
            logger.error(
                "-a/--application and -v/--version required, or --bulk-file required"
            )
            exit(1)

    if not args.no_output_file:
        # Set up a default output file name
        if not args.output_file and args.application and args.version:
            a = "".join([c for c in args.application if re.match(r"\w", c)])
            args.output_file = f"{a}_cves.json"
        elif not args.output_file and args.bulk_file:
            args.output_file = "bulk_cves.json"
        # You should never hit this but I'll default it just in case
        elif not args.output_file:
            args.output_file = "default.json"
    logger.debug(f"Output file: {args.output_file}")

    # Set up arguments
    if args.bulk_file:
        with open(args.bulk_file, "r") as infile:
            inputs = json.loads(infile.read())
    else:
        inputs = {args.application: [args.version]}

    conn = connect_mdb()
    cve_dict = dict()
    for application, versions in inputs.items():
        cves = find_all_cves(conn, application, versions, args.debug)
        cve_dict[application] = cves

    summary = list()
    # Output to terminal
    for application, version_and_dict in cve_dict.items():
        for version, sub_cves in version_and_dict.items():
            total_cve_count = 0
            severity_dict = dict()
            for cve_id, cve in sub_cves.items():
                total_cve_count += 1
                try:
                    severity = cve["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                except KeyError:
                    severity = cve["impact"]["baseMetricV2"]["severity"]
                if severity not in severity_dict.keys():
                    severity_dict[severity] = list()
                severity_dict[severity].append(cve)
                summary.append(
                    {
                        "application": application,
                        "version": version,
                        "cve": cve_id,
                        "severity": severity,
                        "description": cve["cve"]["description"]["description_data"][0][
                            "value"
                        ],
                        "NVD URL": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }
                )

            logger.debug("------------------------------")
            logger.info(
                f"{total_cve_count} vulnerabilities found for {application} {version}"
            )
            for severity, cves in severity_dict.items():
                logger.info(f"- {len(cves)} {severity} severity vulnerabilities")
                for cve in cves:
                    if not args.summary:
                        logger.info(
                            f"\t[{cve['cve']['CVE_data_meta']['ID']}] - {cve['cve']['description']['description_data'][0]['value']}"
                        )

    if not args.no_output_file:
        assert args.output_file is not None
        with open(args.output_file, "w") as outfile:
            if len(summary) == 0:
                logger.info("No vulnerabilities to write. Writing empty file")

            elif args.output_file.endswith(".csv"):
                logger.info(f"Writing summary output to {args.output_file}")
                import csv

                dict_writer = csv.DictWriter(outfile, summary[0].keys())
                dict_writer.writeheader()
                dict_writer.writerows(summary)
            else:
                if args.summary:
                    logger.info(f"Writing summary output to {args.output_file}")
                    outfile.write(json.dumps(summary))
                else:
                    logger.info(f"Writing full output to {args.output_file}")
                    outfile.write(json.dumps(cve_dict, default=str))

    logger.debug("Closing MongoDB connection")
    conn.close()
    logger.debug("Script complete")
