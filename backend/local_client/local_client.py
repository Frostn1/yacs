import psutil
import winapps
import json
import socket
import subprocess
import winreg
import platform
from http.server import BaseHTTPRequestHandler, HTTPServer

LISTEN_PORT = 6612  # Listening port for commands


def human_readable_size(size_in_bytes):
    """Convert bytes to a human-readable format (KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_in_bytes < 1024:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024


def get_windows_version():
    """Fetch detailed Windows version information."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ) as key:
            product_name = winreg.QueryValueEx(key, "ProductName")[
                0
            ]  # e.g., "Windows 10 Home"
            display_version = winreg.QueryValueEx(key, "DisplayVersion")[
                0
            ]  # e.g., "23H2"
            current_build = winreg.QueryValueEx(key, "CurrentBuild")[0]  # e.g., "22631"
            ubr = winreg.QueryValueEx(key, "UBR")[0]  # Update Build Revision
            # Correct "Windows 10" product name for builds exclusive to Windows 11
            if int(current_build) >= 22000:
                product_name = product_name.replace("Windows 10", "Windows 11")
            return {
                "OS": product_name,
                "version": display_version,
                "build": f"{platform.version()}.{ubr}",
            }
    except FileNotFoundError:
        return {"error": "Unable to fetch Windows version. Registry key not found."}
    except Exception as e:
        return {"error": str(e)}


def check_system_stats():
    """Retrieve system statistics including top 5 memory-hungry running processes, CPU, memory, and disk usage."""
    system_stats = {
        "cpu_usage": f"{psutil.cpu_percent(interval=1)}%",
        "memory": {
            "total": human_readable_size(psutil.virtual_memory().total),
            "available": human_readable_size(psutil.virtual_memory().available),
            "used": human_readable_size(psutil.virtual_memory().used),
            "percent": f"{psutil.virtual_memory().percent}%",
        },
        "disk": {
            "total": human_readable_size(psutil.disk_usage("/").total),
            "used": human_readable_size(psutil.disk_usage("/").used),
            "free": human_readable_size(psutil.disk_usage("/").free),
            "percent": f"{psutil.disk_usage('/').percent}%",
        },
        "running_processes": [],
    }

    processes = []
    try:
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            processes.append(
                {
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "cpu_percent": f"{proc.info['cpu_percent']}%",
                    "memory_used": proc.info["memory_info"].rss,  # Raw memory in bytes
                }
            )
    except Exception as e:
        print(f"Error retrieving process information: {e}")

    # Sort processes by memory used (rss) in descending order and take the top 5
    top_processes = sorted(processes, key=lambda x: x["memory_used"], reverse=True)[:5]

    # Format memory_used as human-readable
    for proc in top_processes:
        proc["memory_used"] = human_readable_size(proc["memory_used"])

    system_stats["running_processes"] = top_processes
    return system_stats


def check_open_ports():
    """Collect only TCP and UDP ports in the Listening state."""
    tcp_ports = []
    udp_ports = []

    for conn in psutil.net_connections(kind="inet"):
        try:
            # Collect ports only in the Listening state
            if conn.status == psutil.CONN_LISTEN:
                port_info = {
                    "port": conn.laddr.port,
                    "process": psutil.Process(conn.pid).name()
                    if conn.pid
                    else "Unknown",
                }
                if conn.type == socket.SOCK_STREAM:  # TCP
                    tcp_ports.append(port_info)
                elif conn.type == socket.SOCK_DGRAM:  # UDP
                    udp_ports.append(port_info)
        except psutil.NoSuchProcess:
            port_info = {"port": conn.laddr.port, "process": "Process not found"}
            if conn.type == socket.SOCK_STREAM:  # TCP
                tcp_ports.append(port_info)
            elif conn.type == socket.SOCK_DGRAM:  # UDP
                udp_ports.append(port_info)
        except Exception as e:
            print(f"Error collecting port info: {e}")

    return {"Tcp": tcp_ports, "Udp": udp_ports}


def check_installed_apps():
    """Retrieve a list of installed applications with their versions."""
    installed_apps = []
    try:
        for app in winapps.list_installed():
            installed_apps.append(
                {"name": app.name, "version": app.version if app.version else "Unknown", "vendor": app.publisher}
            )
    except Exception as e:
        print(f"Error retrieving installed apps: {e}")
    return installed_apps


def check_firewall_state():
    """Check if the Windows Firewall is enabled for each profile."""
    try:
        output = subprocess.check_output(
            [
                "powershell",
                "-Command",
                "Get-NetFirewallProfile | Select-Object Name, Enabled",
            ],
            stderr=subprocess.STDOUT,
            text=True,
        )
        firewall_states = {}
        # Parse the output by ignoring headers and empty lines
        lines = output.strip().splitlines()
        for line in lines[2:]:  # Skip the first two header lines
            parts = line.split()
            if len(parts) >= 2:  # Ensure the line has both Name and Enabled fields
                profile_name = parts[0]
                enabled_state = parts[1] == "True"
                firewall_states[profile_name] = enabled_state
        return firewall_states
    except Exception as e:
        return {"error": str(e)}


def check_antivirus_status():
    """Retrieve detailed antivirus status for Windows Defender."""
    try:
        # Execute PowerShell command to retrieve antivirus details
        output = subprocess.check_output(
            ["powershell", "-Command", "Get-MpComputerStatus | Format-List"],
            stderr=subprocess.STDOUT,
            text=True,
        )

        # Parse PowerShell output into a dictionary
        status = {}
        for line in output.splitlines():
            if ":" in line:
                key, value = map(str.strip, line.split(":", 1))
                status[key] = value

        # Normalize keys and extract relevant details
        normalized_status = {
            "EngineVersion": status.get("AMEngineVersion", "Unknown"),
            "ProductVersion": status.get("AMProductVersion", "Unknown"),
            "RealTimeProtection": "Enabled"
            if status.get("RealTimeProtectionEnabled", "False") == "True"
            else "Disabled",
            "Antispyware": "Enabled"
            if status.get("AntispywareEnabled", "False") == "True"
            else "Disabled",
            "AntispywareSignatureLastUpdated": status.get(
                "AntispywareSignatureLastUpdated", "Unknown"
            ),
            "AntispywareSignatureVersion": status.get(
                "AntispywareSignatureVersion", "Unknown"
            ),
            "Antivirus": "Enabled"
            if status.get("AntivirusEnabled", "False") == "True"
            else "Disabled",
            "AntivirusSignatureLastUpdated": status.get(
                "AntivirusSignatureLastUpdated", "Unknown"
            ),
            "AntivirusSignatureVersion": status.get(
                "AntivirusSignatureVersion", "Unknown"
            ),
        }

        return normalized_status
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to retrieve Windows Defender status: {str(e)}"}
    except Exception as e:
        return {
            "error": f"Unexpected error occurred while retrieving antivirus status: {str(e)}"
        }


def check_smb_version():
    """Check the status of SMB1, SMB2, and SMB3 protocols with proper error handling."""
    smb_status = {}

    # Check SMB1 status
    try:
        smb1_output = subprocess.run(
            [
                "powershell",
                "-Command",
                "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        output_text = smb1_output.stdout.strip()

        if "State            : Enabled" in output_text:
            smb_status["SMB1_installed"] = True
            smb_status["SMB1_status"] = "Enabled"
        elif "State            : Disabled" in output_text:
            smb_status["SMB1_installed"] = True
            smb_status["SMB1_status"] = "Disabled"
        else:
            smb_status["SMB1_installed"] = False
            smb_status["SMB1_status"] = "Not Installed"
    except subprocess.CalledProcessError as e:
        smb_status["SMB1_installed"] = False
        smb_status["SMB1_status"] = f"Error checking SMB1: {e.stderr.strip() or str(e)}"
    except Exception as e:
        smb_status["SMB1_installed"] = False
        smb_status["SMB1_status"] = f"Unexpected error: {str(e)}"

    # Check SMB2/SMB3 status
    try:
        smb2_output = subprocess.run(
            [
                "powershell",
                "-Command",
                "Get-SmbServerConfiguration | Select-Object EnableSMB2Protocol",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        smb_status["SMB2_enabled"] = "True" in smb2_output.stdout
    except subprocess.CalledProcessError as e:
        smb_status["SMB2_enabled"] = False
        smb_status["SMB2_status"] = f"Error checking SMB2: {e.stderr.strip() or str(e)}"
    except Exception as e:
        smb_status["SMB2_enabled"] = False
        smb_status["SMB2_status"] = f"Unexpected error: {str(e)}"

    return smb_status


def check_rdp_settings():
    """Check if RDP is enabled and retrieve its listening port."""
    try:
        # Check if RDP is enabled
        registry_output = subprocess.check_output(
            [
                "powershell",
                "-Command",
                'Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" | Select-Object -ExpandProperty fDenyTSConnections',
            ],
            stderr=subprocess.STDOUT,
            text=True,
        )
        rdp_enabled = (
            registry_output.strip() == "0"
        )  # fDenyTSConnections = 0 means RDP is enabled

        # Query the RDP port number explicitly
        port_output = subprocess.check_output(
            [
                "powershell",
                "-Command",
                '(Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp").PortNumber',
            ],
            stderr=subprocess.STDOUT,
            text=True,
        )
        port_number = (
            int(port_output.strip()) if port_output.strip().isdigit() else None
        )

        return {
            "rdp_enabled": rdp_enabled,
            "rdp_port": port_number,
            "status": f"RDP is enabled and listening on port {port_number}"
            if rdp_enabled and port_number
            else "RDP is enabled but no listening port found.",
        }
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to retrieve RDP settings: {str(e)}"}
    except Exception as e:
        return {
            "error": f"Unexpected error occurred while retrieving RDP settings: {str(e)}"
        }


def check_local_users():
    """Retrieve a list of local users on the system."""
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", "Get-LocalUser | Select-Object Name, Enabled"],
            stderr=subprocess.STDOUT,
            text=True,
        )
        users = []
        lines = output.strip().splitlines()
        for line in lines[3:]:  # Skip headers
            parts = line.split()
            if len(parts) >= 2:
                users.append({"name": parts[0], "enabled": parts[1] == "True"})
        return users
    except Exception as e:
        return {"error": str(e)}


def check_shared_folders():
    """Retrieve a list of shared folders on the system."""
    try:
        output = subprocess.check_output(
            [
                "powershell",
                "-Command",
                "Get-SmbShare | Select-Object Name, Path, Description",
            ],
            stderr=subprocess.STDOUT,
            text=True,
        )
        shares = []
        lines = output.strip().splitlines()

        # Skip header lines and validate each row
        for line in lines[1:]:  # Skip the header row
            parts = line.split(
                None, 2
            )  # Split into at most 3 parts (Name, Path, Description)
            if len(parts) >= 2 and parts[0] not in [
                "----",
                "",
            ]:  # Exclude invalid or header-like rows
                shares.append(
                    {
                        "name": parts[0],
                        "path": parts[1],
                        "description": parts[2] if len(parts) > 2 else "",
                    }
                )
        return shares
    except Exception as e:
        return {"error": str(e)}


def collect_data():
    """Collect system information and check for misconfigurations."""
    os_version = get_windows_version()
    system_stats = check_system_stats()
    open_ports = check_open_ports()
    installed_apps = check_installed_apps()
    firewall_state = check_firewall_state()
    antivirus_status = check_antivirus_status()
    smb_status = check_smb_version()
    rdp_settings = check_rdp_settings()
    local_users = check_local_users()
    shared_folders = check_shared_folders()

    # Compile all data into a single dictionary
    data = {
        "os_version": os_version,
        "system_stats": system_stats,
        "open_ports": open_ports,
        "installed_apps": installed_apps,
        "firewall_state": firewall_state,
        "antivirus_status": antivirus_status,
        "smb_status": smb_status,
        "rdp_settings": rdp_settings,
        "local_users": local_users,
        "shared_folders": shared_folders,
    }
    print("Collected Data:", json.dumps(data, indent=2))  # Debug output
    return data


def save_data_locally(data):
    """Save the collected data to a local JSON file."""
    with open("collected_data.json", "w") as f:
        json.dump(data, f, indent=4)


class AgentHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handle POST requests."""
        if self.path == "/":
            content_length = int(self.headers["Content-Length"])
            post_data = json.loads(self.rfile.read(content_length).decode("utf-8"))

            if post_data.get("command") == "SCAN":
                print("Received SCAN command. Collecting data...")
                data = collect_data()

                # Save locally to collected_data.json
                with open("collected_data.json", "w") as f:
                    json.dump(data, f, indent=4)

                # Send collected data back to the server
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"data": data}).encode("utf-8"))
                print("Data collected and sent back.")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Unknown command")
        else:
            self.send_response(404)
            self.end_headers()


def run_agent():
    """Start the agent's HTTP server."""
    server_address = ("0.0.0.0", LISTEN_PORT)
    httpd = HTTPServer(server_address, AgentHandler)
    print(f"Agent listening on port {LISTEN_PORT}...")
    httpd.serve_forever()


if __name__ == "__main__":
    print("Starting client agent...")
    run_agent()
