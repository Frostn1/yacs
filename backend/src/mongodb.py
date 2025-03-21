from os import getenv
from typing import Iterable
from pymongo import MongoClient, UpdateOne
from pymongo.collection import Collection
from loguru import logger

DEFAULT_MONGO_URI = "localhost:27017"
MONGO_URI = getenv("MONGO_URI", DEFAULT_MONGO_URI)
if MONGO_URI == DEFAULT_MONGO_URI:
    logger.warning(f"[!] MONGO_URI is not set, using default : {DEFAULT_MONGO_URI}")

client = MongoClient(MONGO_URI)
threatmesh_db = client.ThreatMesh
collected_data_collection = threatmesh_db.collected_data
cve_collection = threatmesh_db.cves
meta_collection = threatmesh_db.meta


def update_cves_in_collection(cve_collection: Collection, cves: Iterable[dict]) -> None:
    ops = [
        UpdateOne(filter={'cve.CVE_data_meta.ID': cve['cve']['CVE_data_meta']['ID']}, update={'$set': cve}, upsert=True)
        for cve in cves
    ]
    cve_collection.bulk_write(ops)
    logger.debug("Finished insertion")


logger.info("[V] Connected successfully to ThreatMesh DB")
__ALL__ = [
    "threatmesh_db",
    "collected_data_collection",
    "cve_collection",
    "meta_collection",
]
