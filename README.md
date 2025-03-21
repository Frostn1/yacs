# YACS – Yet Another CVE Searcher

## Description

YACS (Yet Another CVE Searcher) is a command-line tool designed to search and mirror Common Vulnerabilities and Exposures (CVE) data from the National Vulnerability Database (NVD) into a MongoDB instance. It allows developers to quickly query for known security vulnerabilities based on vendor, product, and version.

## Features

- **Search CVEs**: Look up vulnerabilities for specific products, vendors, and versions.
- **Mirror NVD**: Download and update CVE data from the National Vulnerability Database into a local MongoDB.
- **Flexible Querying**: Search with or without product normalization and filter by vendor and version.

## Setup

### Prerequisites

Ensure you have the following installed:

- **Python 3.8+** – Download [here](https://www.python.org/downloads/)
- **MongoDB** – [Installation guide](https://docs.mongodb.com/manual/installation/)
- **pip** – Comes pre-installed with Python

### Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/Frostn1/yacs.git
   cd yacs
   ```

2. Install dependencies:

   ```sh
   pip install -r requirements.txt
   ```

3. Ensure MongoDB is running:

   ```sh
   mongod --dbpath /your/db/path
   ```

4. Verify the setup:
   ```sh
   python yacs.py --help
   ```

## Usage

### Mirroring NVD Data

To create a local mirror of the NVD database in MongoDB:

```sh
python yacs.py mirror
```

This command will download and update all CVE records without any limitations.

## Example Search

To search for a CVE in Windows 11 version 10.0.26100.3476:

```sh
python yacs.py search windows_11_24h2 --version 10.0.26100.3476 --vendor microsoft --dont-normalize-product
```

## Contributing

Contributions are welcome! Feel free to submit pull requests or report issues.

## License

This project is licensed under the MIT License.

## Contact

For issues or inquiries, contact: aui.svi@gmail.com
