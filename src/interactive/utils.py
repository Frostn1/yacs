from typing import Iterable
from mongodb import MongoDBClient


def fetch_vendors() -> Iterable[str]:
    with MongoDBClient() as mdb_client:
        cve_collection = mdb_client.nvd_mirror.cves

        vendors = cve_collection.aggregate(
            [
                {"$unwind": "$configurations.nodes"},
                {"$unwind": "$configurations.nodes.cpe_match"},
                {
                    "$project": {
                        "vendor_name": {
                            "$arrayElemAt": [
                                {
                                    "$split": [
                                        "$configurations.nodes.cpe_match.cpe23Uri",
                                        ":",
                                    ]
                                },
                                3,
                            ]
                        }
                    }
                },
                {"$group": {"_id": "$vendor_name"}},
            ]
        )

        return [vendor["_id"] for vendor in vendors]


def fetch_products() -> Iterable[str]:
    with MongoDBClient() as mdb_client:
        cve_collection = mdb_client.nvd_mirror.cves

        products = cve_collection.aggregate(
            [
                {"$unwind": "$configurations.nodes"},
                {"$unwind": "$configurations.nodes.cpe_match"},
                {
                    "$project": {
                        "product_name": {
                            "$arrayElemAt": [
                                {
                                    "$split": [
                                        "$configurations.nodes.cpe_match.cpe23Uri",
                                        ":",
                                    ]
                                },
                                4,
                            ]
                        }
                    }
                },
                {"$group": {"_id": "$product_name"}},
            ]
        )

        return [product["_id"] for product in products]
