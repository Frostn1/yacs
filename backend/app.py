from dataclasses import asdict
from loguru import logger
from src.nvd.mirror_nvd import setup_db
from src.collected_data import CollectedData
from src.cve_searcher.search_vulnerabilties import search_vulnerabilities
from src.mongodb import collected_data_collection, cve_collection, meta_collection
from src.poller import poll_endpoint
from src.utils import is_ipaddress
from flask import Flask, Response, request, jsonify
import asyncio
import hypercorn.asyncio
from hypercorn.config import Config
import sys

app = Flask(__name__)
logger.remove()
logger.add(sys.stderr, level="INFO")


@app.route("/poll", methods=["POST"])
def poll() -> tuple[Response, int]:
    """
    Poll pc endpoints, and save result to collection

    Request.body: {
        ips: [<ip_1>: str, <ip_2>: str]
    }

    Returns:
        tuple[Response, int]: Response, http status
    """

    ip_list = request.json.get("ips", None)
    if ip_list is None:
        return jsonify({"error": "Missing IP list, `ips`"}), 400
    if not isinstance(ip_list, list) or not all(map(is_ipaddress, ip_list)):
        return jsonify(
            {"error": "Not all arguments in IP list are valid ip addresses"}
        ), 400

    scan_results = []
    for ip in ip_list:
        try:
            collected_data = poll_endpoint(ip)
            scan_results.append({"ip": ip, "status": "Data collected successfully"})
        except Exception as e:
            scan_results.append({"ip": ip, "status": f'Failed: {str(e)}'})
        else:
            collected_data_collection.update_one(
                {"ip_address": ip}, {"$set": asdict(collected_data)}, upsert=True
            )
            logger.info(f"[V] Data saved successfully for < {ip} >")

    return jsonify(
        {"message": "Scan and CVE search completed", "results": scan_results}
    ), 200


@app.route("/scan", methods=["GET"])
def scan() -> tuple[Response, int]:
    """
    Scan NVD mirror for vulnerabilities, using collected data collection for paramters.

    Returns:
        tuple[Response, int]: Response, http status
    """
    logger.info("Scanning Records")
    records = collected_data_collection.find({})

    for record in records:
        logger.info(f"Scanning record from ip : {record['ip_address']}")

        cd = CollectedData(**record)

        vulns = {
            "os_version": [
                cvematch.cve
                for cvematch in search_vulnerabilities(
                    cve_collection, cd.os_version.query
                )
            ],
            "installed_apps": list(filter(lambda ia: len(ia["cves"]),[
                {
                    "name": installed_app.name,
                    "version": installed_app.version,
                    "cves": [
                        cvematch.cve
                        for cvematch in search_vulnerabilities(
                            cve_collection, installed_app.query
                        )
                    ],
                }
                for installed_app in cd.installed_apps
            ])),
        }

        record["vulnerabilities"] = vulns
        collected_data_collection.update_one({"_id": record["_id"]}, {"$set": record})
    logger.info("Finished scanning")

    return jsonify({}), 200


@app.route("/install_db", methods=["GET"])
def install_db() -> tuple[Response, int]:
    """
    Install a new NVD mirror db

    Returns:
        tuple[Response, int]: Response, http status
    """
    setup_db(cve_collection, meta_collection)
    return jsonify({"message": "Installed DB succesfully"}), 200


@app.route("/")
def home():
    return "ThreatMesh Backend is Running!"


async def main():
        
    config = Config()
    config.bind = ["127.0.0.1:5000"]
    await hypercorn.asyncio.serve(app, config)


if __name__ == "__main__":
    asyncio.run(main())
