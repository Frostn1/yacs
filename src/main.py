from src.mdb_client import MongoDBClient
from src.mirror_nvd import update_checkpoints, update_cves


def main() -> None:
    with MongoDBClient() as mdb_client:
        meta_collection = mdb_client["nvd"]["meta"]
        cve_collection = mdb_client["nvd"]["cves"]
        update_checkpoints(meta_collection)
        update_cves(cve_collection)


if __name__ == "__main__":
    main()
