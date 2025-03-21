from http.server import BaseHTTPRequestHandler, HTTPServer
import json
DATA = {
    "os_version": {
        "OS": "Windows 11 Pro",
        "version": "23H2",
        "build": "10.0.22631.4751"
    },
    "system_stats": {
        "cpu_usage": "2.2%",
        "memory": {
            "total": "31.21 GB",
            "available": "17.63 GB",
            "used": "13.59 GB",
            "percent": "43.5%"
        },
        "disk": {
            "total": "1.82 TB",
            "used": "816.85 GB",
            "free": "1.02 TB",
            "percent": "43.9%"
        },
        "running_processes": [
            {
                "pid": 19844,
                "name": "chrome.exe",
                "cpu_percent": "16.0%",
                "memory_used": "809.17 MB"
            },
            {
                "pid": 24868,
                "name": "chrome.exe",
                "cpu_percent": "0.4%",
                "memory_used": "716.82 MB"
            },
            {
                "pid": 10496,
                "name": "Code.exe",
                "cpu_percent": "0.1%",
                "memory_used": "526.42 MB"
            },
            {
                "pid": 3964,
                "name": "Code.exe",
                "cpu_percent": "0.1%",
                "memory_used": "501.67 MB"
            },
            {
                "pid": 9424,
                "name": "Postman.exe",
                "cpu_percent": "0.1%",
                "memory_used": "385.75 MB"
            }
        ]
    },
    "open_ports": {
        "Tcp": [
            {
                "port": 7680,
                "process": "svchost.exe"
            },
            {
                "port": 49667,
                "process": "svchost.exe"
            },
            {
                "port": 5432,
                "process": "postgres.exe"
            },
            {
                "port": 49665,
                "process": "wininit.exe"
            },
            {
                "port": 3389,
                "process": "svchost.exe"
            },
            {
                "port": 445,
                "process": "System"
            },
            {
                "port": 15611,
                "process": "Postman.exe"
            },
            {
                "port": 6612,
                "process": "python.exe"
            },
            {
                "port": 28385,
                "process": "System"
            },
            {
                "port": 59869,
                "process": "logioptionsplus_agent.exe"
            },
            {
                "port": 135,
                "process": "svchost.exe"
            },
            {
                "port": 9053,
                "process": "java.exe"
            },
            {
                "port": 5432,
                "process": "postgres.exe"
            },
            {
                "port": 3389,
                "process": "svchost.exe"
            },
            {
                "port": 9052,
                "process": "java.exe"
            },
            {
                "port": 139,
                "process": "System"
            },
            {
                "port": 49664,
                "process": "lsass.exe"
            },
            {
                "port": 49350,
                "process": "esrv_svc.exe"
            },
            {
                "port": 9051,
                "process": "java.exe"
            },
            {
                "port": 5000,
                "process": "python.exe"
            },
            {
                "port": 49665,
                "process": "wininit.exe"
            },
            {
                "port": 139,
                "process": "System"
            },
            {
                "port": 9053,
                "process": "java.exe"
            },
            {
                "port": 27017,
                "process": "mongod.exe"
            },
            {
                "port": 49667,
                "process": "svchost.exe"
            },
            {
                "port": 9051,
                "process": "java.exe"
            },
            {
                "port": 15611,
                "process": "Postman.exe"
            },
            {
                "port": 49664,
                "process": "lsass.exe"
            },
            {
                "port": 28390,
                "process": "System"
            },
            {
                "port": 7680,
                "process": "svchost.exe"
            },
            {
                "port": 49668,
                "process": "spoolsv.exe"
            },
            {
                "port": 445,
                "process": "System"
            },
            {
                "port": 49666,
                "process": "svchost.exe"
            },
            {
                "port": 9100,
                "process": "lghub_updater.exe"
            },
            {
                "port": 9180,
                "process": "lghub_updater.exe"
            },
            {
                "port": 49679,
                "process": "services.exe"
            },
            {
                "port": 24830,
                "process": "AsusSoftwareManager.exe"
            },
            {
                "port": 9054,
                "process": "java.exe"
            },
            {
                "port": 27015,
                "process": "AppleMobileDeviceService.exe"
            },
            {
                "port": 135,
                "process": "svchost.exe"
            },
            {
                "port": 9054,
                "process": "java.exe"
            },
            {
                "port": 5354,
                "process": "mDNSResponder.exe"
            },
            {
                "port": 49668,
                "process": "spoolsv.exe"
            },
            {
                "port": 49666,
                "process": "svchost.exe"
            },
            {
                "port": 49351,
                "process": "esrv.exe"
            },
            {
                "port": 139,
                "process": "System"
            },
            {
                "port": 49679,
                "process": "services.exe"
            },
            {
                "port": 9052,
                "process": "java.exe"
            },
            {
                "port": 8080,
                "process": "httpd.exe"
            },
            {
                "port": 912,
                "process": "vmware-authd.exe"
            },
            {
                "port": 902,
                "process": "vmware-authd.exe"
            },
            {
                "port": 5040,
                "process": "svchost.exe"
            }
        ],
        "Udp": []
    },
    "installed_apps": [
        {
            "name": "Mozilla Firefox (x64 en-US)",
            "vendor": "Mozilla",
            "version": "105.0"
        },
        {
            "name": "WinRAR (64-bit)",
            "vendor": "RARLAB",
            "version": "4.00.0"
        }
    ],
    "firewall_state": {
        "Domain": True,
        "Private": True,
        "Public": True
    },
    "antivirus_status": {
        "EngineVersion": "1.1.24090.11",
        "ProductVersion": "4.18.24090.11",
        "RealTimeProtection": "Enabled",
        "Antispyware": "Enabled",
        "AntispywareSignatureLastUpdated": "1/29/2025 8:15:57 AM",
        "AntispywareSignatureVersion": "1.421.1592.0",
        "Antivirus": "Enabled",
        "AntivirusSignatureLastUpdated": "1/29/2025 8:15:55 AM",
        "AntivirusSignatureVersion": "1.421.1592.0"
    },
    "smb_status": {
        "SMB1_installed": True,
        "SMB1_status": "Enabled",
        "SMB2_enabled": True
    },
    "rdp_settings": {
        "rdp_enabled": True,
        "rdp_port": 3389,
        "status": "RDP is enabled and listening on port 3389"
    },
    "local_users": [
        {
            "name": "DefaultAccount",
            "enabled": False
        },
        {
            "name": "Guest",
            "enabled": False
        },
        {
            "name": "Ilan",
            "enabled": True
        },
        {
            "name": "postgres",
            "enabled": True
        },
        {
            "name": "WDAGUtilityAccount",
            "enabled": False
        }
    ],
    "shared_folders": [
        {
            "name": "ADMIN$",
            "path": "C:\\Windows",
            "description": "Remote Admin "
        },
        {
            "name": "C$",
            "path": "C:\\",
            "description": "Default share"
        },
        {
            "name": "IPC$",
            "path": "Remote",
            "description": "IPC"
        }
    ]
}
class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type','application/json')
        self.end_headers()
        body = {
            "data": DATA
        }
        self.wfile.write(json.dumps(body).encode())

print('[V] Client running on port: 6612')
with HTTPServer(('', 6612), handler) as server:
    server.serve_forever()