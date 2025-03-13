# YACS - Yet Another CVE Searcher

## Overview
YACS (Yet Another CVE Searcher) is a command-line tool for searching CVEs (Common Vulnerabilities and Exposures) and mirroring the NVD (National Vulnerability Database) into MongoDB. It helps you find known vulnerabilities in software products and maintain a local copy of the NVD for offline analysis.

## Installation
### Prerequisites
Ensure you have the following installed:
- Python 3
- [MongoDB](https://www.mongodb.com/docs/manual/installation/)

### Setup
1. Clone the repository:
   ```sh
   git clone https://github.com/Frostn1/yacs
   cd yacs
   ```
2. Install dependencies using `pyproject.toml`:
   ```sh
   pip install .
   ```

## Usage
### Mirror NVD Data
To mirror the NVD database to a local MongoDB instance:
```sh
python -m yacs mirror --initial
```
or using [uv](https://github.com/astral-sh/uv):
```sh
uv run python -m yacs mirror --initial
```
Options:
- `--initial`: Perform an initial mirror install from NVD to MongoDB.
- `--sync`: Synchronize the local mirror with NVD.
- `--year-start <year>`: Start year for mirroring (default: earliest available year).
- `--year-end <year>`: End year for mirroring (default: latest available year).

### Search for CVEs
To search for CVEs in the local mirror:
```sh
python -m yacs search <product> --vendor <vendor> --version <version>
```
or using uv:
```sh
uv run python -m yacs search <product> --vendor <vendor> --version <version>
```
Options:
- `<product>`: Product name to search for.
- `--vendor <vendor>`: Vendor name (optional).
- `--version <version>`: Version number (optional, default is `0`).
- `--dont-normalize-product`: Disable product name normalization when searching.
- `--file <file>`: Use a file containing search parameters instead of command-line arguments.

### Search Format File
You can also search using a JSON file with an array of query objects. Each object can have the following keys:
- `vendor` (optional): Vendor name.
- `product` (required): Product name.
- `version` (optional): Product version.
- `normalize_product_name` (optional, default: `true`): Whether to normalize the product name.

#### Example JSON File
```json
[
  {
    "vendor": "mozilla",
    "product": "firefox",
    "version": "89.0",
    "normalize_product_name": true
  },
  {
    "vendor": "microsoft",
    "product": "windows",
    "version": "10",
    "normalize_product_name": false
  }
]
```
To use this file for searching, run:
```sh
python -m yacs search --file queries.json
```
or using uv:
```sh
uv run python -m yacs search --file queries.json
```

### Example Searches
#### Example 1: Search for a CVE by product and version
```sh
python -m yacs search firefox --version 89.0
```
or
```sh
uv run python -m yacs search firefox --version 89.0
```
#### Example 2: Mirror NVD data from 2010 to 2025
```sh
python -m yacs mirror --year-start 2010 --year-end 2025
```
or
```sh
uv run python -m yacs mirror --year-start 2010 --year-end 2025
```

## Features
- **Search CVEs**: Look up vulnerabilities for specific products, vendors, and versions.
- **Mirror NVD**: Download and update CVE data from the National Vulnerability Database into a local MongoDB.
- **Flexible Querying**: Search with or without product normalization and filter by vendor and version.

## Contributing
Contributions are welcome! Feel free to submit pull requests or report issues.

## License
This project is licensed under the MIT License.

## Contact
For issues or inquiries, contact: aui.svi@gmail.com

