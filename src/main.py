from src.mdb_client import MongoDBClient
from src.nvd.mirror_nvd import download_cves, download_metafiles, smart_download_cves


with MongoDBClient() as client:
    cve_collection = client['nvd_mirror']['cves']
    meta_collection = client['nvd_mirror']['meta']
    # download_metafiles(meta_collection, range(2002, 2004))
    # download_cves(cve_collection, range(2002, 2004))
    smart_download_cves(cve_collection, meta_collection)