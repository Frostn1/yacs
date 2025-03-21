# ThreatMesh

## Introduction
ThreatMesh is a cybersecurity tool designed to scan endpoints for vulnerabilities by polling system data and cross-referencing it with the National Vulnerability Database (NVD). It provides an automated way to detect security risks based on installed applications and operating system versions, helping organizations stay ahead of potential threats.

## How It Works
ThreatMesh operates through a Flask-based backend, offering RESTful APIs to collect system data, scan for vulnerabilities, and manage a local NVD mirror database.

### Key Components:
1. **Polling System Data (`/poll`)**
   - Accepts a list of IP addresses.
   - Collects system data from each endpoint.
   - Stores the collected data in a MongoDB collection.

2. **Scanning for Vulnerabilities (`/scan`)**
   - Retrieves stored system data.
   - Searches for known vulnerabilities using NVD mirror data.
   - Updates the database with detected CVEs (Common Vulnerabilities and Exposures).

3. **Database Setup (`/install_db`)**
   - Initializes a local NVD mirror database.
   - Ensures up-to-date CVE records for scanning.

4. **Web Server**
   - Uses Hypercorn (an ASGI server) to run asynchronously.
   - Logs operations using `loguru` for structured logging.

## Features
- **Automated Endpoint Scanning:** Polls multiple endpoints simultaneously.
- **CVE Lookup:** Cross-references system data with NVD.
- **Database Management:** Supports setting up and maintaining an offline NVD mirror.
- **REST API:** Provides easy integration with security monitoring systems.
- **Logging & Error Handling:** Uses structured logging for insights and debugging.

## How to Use

### Prerequisites
- Python 3.8+
- MongoDB
- Required Python packages (install using `pip install -r requirements.txt`)

### Running the Application
1. **Start the backend:**
   ```sh
   python main.py
   ```
2. **Poll endpoints:**
   ```sh
   curl -X POST http://127.0.0.1:5000/poll -H "Content-Type: application/json" -d '{"ips": ["192.168.1.1", "192.168.1.2"]}'
   ```
3. **Scan for vulnerabilities:**
   ```sh
   curl -X GET http://127.0.0.1:5000/scan
   ```
4. **Initialize the NVD database:**
   ```sh
   curl -X GET http://127.0.0.1:5000/install_db
   ```
5. **Check if the backend is running:**
   ```sh
   curl http://127.0.0.1:5000/
   ```

## Future Enhancements
- **User Authentication:** Secure API endpoints.
- **Web Dashboard:** UI for monitoring vulnerabilities.
- **Scheduled Scans:** Automate scanning at regular intervals.
- **Integration with SIEM Systems:** Connect with security event management tools.

ThreatMesh provides a powerful foundation for cybersecurity threat detection and vulnerability management.

