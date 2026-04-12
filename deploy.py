"""
Mobile Security Agent - VPS Deployment Script
Automates full deployment to a Vultr Ubuntu VPS via SSH/SFTP.
Run: python deploy.py
"""
import os
import sys
import time
import socket
import getpass
import paramiko
from pathlib import Path

# Force UTF-8 output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ===============================================
#  VPS Configuration
# ===============================================
VPS_HOST = "95.179.206.68"
VPS_USER = "root"
VPS_PASS = r"Q5]j5*kpx)MyxnLz"
VPS_PORT = 22
APP_PORT = 8000
REMOTE_DIR = "/root/mobile-security-agent"

# Local project directory
LOCAL_DIR = Path(__file__).resolve().parent

# Files/folders to skip during upload
SKIP = {"__pycache__", ".git", "chroma_db", "uploads", "reports", "logs", "deploy.py", ".pyc", "venv"}


def banner():
    print("\n" + "=" * 55)
    print("  [SHIELD] Mobile Security Agent - VPS Deployer")
    print(f"  Target: {VPS_HOST}:{APP_PORT}")
    print("=" * 55 + "\n")


def create_ssh_client():
    """Create and return an SSH client connected to the VPS."""
    print(f"[*] Connecting to {VPS_HOST}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for attempt in range(3):
        password = VPS_PASS if attempt == 0 else input("  Re-enter password: ").strip()
        try:
            client.connect(VPS_HOST, port=VPS_PORT, username=VPS_USER, password=password, timeout=30)
            print(f"[+] Connected to {VPS_HOST} as {VPS_USER}")
            return client
        except paramiko.AuthenticationException:
            print(f"[!] Auth failed (attempt {attempt+1}/3). Wrong password.")
        except socket.timeout:
            print("[!] Connection timed out.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Connection error: {e}")
            sys.exit(1)

    print("[!] All 3 attempts failed. Exiting.")
    sys.exit(1)


def run_cmd(client, cmd, show_output=True):
    """Run a command on the remote server."""
    if show_output:
        print(f"  > {cmd[:80]}{'...' if len(cmd) > 80 else ''}")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=300)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="ignore").strip()
    err = stderr.read().decode("utf-8", errors="ignore").strip()
    if show_output and out:
        for line in out.split("\n")[:15]:
            print(f"    {line}")
    if err and exit_code != 0:
        for line in err.split("\n")[:8]:
            print(f"    [ERR] {line}")
    return exit_code, out, err


def upload_directory(sftp, local_path, remote_path):
    """Recursively upload a directory via SFTP."""
    try:
        sftp.stat(remote_path)
    except FileNotFoundError:
        sftp.mkdir(remote_path)

    for item in os.listdir(local_path):
        if item in SKIP or item.endswith(".pyc"):
            continue

        local_item = os.path.join(local_path, item)
        remote_item = f"{remote_path}/{item}"

        if os.path.isdir(local_item):
            upload_directory(sftp, local_item, remote_item)
        else:
            file_size = os.path.getsize(local_item)
            if file_size > 0:
                size_str = f"{file_size / 1024:.1f}KB" if file_size > 1024 else f"{file_size}B"
                print(f"    UP: {item} ({size_str})")
                sftp.put(local_item, remote_item)


def upload_project(client):
    """Upload the entire project to the VPS."""
    print(f"\n[*] Uploading project to {REMOTE_DIR}...")

    sftp = client.open_sftp()

    # Clean and recreate remote dir
    run_cmd(client, f"rm -rf {REMOTE_DIR}", show_output=False)
    run_cmd(client, f"mkdir -p {REMOTE_DIR}", show_output=False)

    upload_directory(sftp, str(LOCAL_DIR), REMOTE_DIR)
    sftp.close()

    print("[+] Project uploaded successfully!")


def setup_server(client):
    """Install dependencies and configure the server."""
    print("\n[*] Setting up server environment...")

    commands = [
        ("Updating packages...",
         "apt-get update -qq 2>/dev/null"),

        ("Installing Python...",
         "apt-get install -y -qq python3 python3-pip python3-venv curl 2>/dev/null"),

        ("Creating virtual environment...",
         f"cd {REMOTE_DIR} && python3 -m venv venv"),

        ("Installing Python dependencies...",
         f"cd {REMOTE_DIR} && source venv/bin/activate && "
         f"pip install --quiet fastapi uvicorn python-multipart aiofiles pydantic 2>/dev/null"),

        ("Creating directories...",
         f"mkdir -p {REMOTE_DIR}/uploads {REMOTE_DIR}/reports {REMOTE_DIR}/logs"),

        ("Configuring firewall...",
         f"ufw allow {APP_PORT}/tcp 2>/dev/null; ufw allow 22/tcp 2>/dev/null; echo 'Firewall configured'"),
    ]

    for desc, cmd in commands:
        print(f"\n[*] {desc}")
        exit_code, out, err = run_cmd(client, cmd)
        if exit_code != 0:
            print(f"  [WARN] {desc} exit code: {exit_code}")

    print("\n[+] Server environment ready!")


def create_systemd_service(client):
    """Create a systemd service for auto-start on boot."""
    print("\n[*] Creating systemd service...")

    service = (
        "[Unit]\n"
        "Description=Mobile Security Agent\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "User=root\n"
        f"WorkingDirectory={REMOTE_DIR}/backend\n"
        f"Environment=PATH={REMOTE_DIR}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n"
        f"ExecStart={REMOTE_DIR}/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port {APP_PORT}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )

    # Write service file via SFTP
    sftp = client.open_sftp()
    with sftp.open("/etc/systemd/system/msa.service", "w") as f:
        f.write(service)
    sftp.close()

    # Enable and start
    cmds = [
        "systemctl daemon-reload",
        "systemctl stop msa 2>/dev/null; sleep 1; echo stopped",
        "systemctl enable msa",
        "systemctl start msa",
    ]
    for cmd in cmds:
        run_cmd(client, cmd, show_output=False)

    time.sleep(4)

    # Check status
    exit_code, out, err = run_cmd(client, "systemctl is-active msa")
    if "active" in out:
        print("[+] Service is ACTIVE and running!")
    else:
        print("[!] Service may not be running. Checking logs...")
        run_cmd(client, "journalctl -u msa --no-pager -n 25")


def verify_deployment(client):
    """Verify the deployment is working."""
    print("\n[*] Verifying deployment...")
    time.sleep(3)

    exit_code, out, err = run_cmd(client, f"curl -s http://localhost:{APP_PORT}/api/health")
    if "healthy" in out:
        print("[+] Health check PASSED!")
        return True
    else:
        print("[!] Health check failed. Checking logs...")
        run_cmd(client, "journalctl -u msa --no-pager -n 30")
        return False


def main():
    banner()

    # Step 1: Connect
    client = create_ssh_client()

    try:
        # Step 2: Upload project files
        upload_project(client)

        # Step 3: Install dependencies
        setup_server(client)

        # Step 4: Create systemd service
        create_systemd_service(client)

        # Step 5: Verify
        success = verify_deployment(client)

        # Summary
        print("\n" + "=" * 55)
        if success:
            print("  DEPLOYMENT COMPLETE!")
            print(f"\n  Dashboard:  http://{VPS_HOST}:{APP_PORT}")
            print(f"  API Docs:   http://{VPS_HOST}:{APP_PORT}/docs")
            print(f"  Health:     http://{VPS_HOST}:{APP_PORT}/api/health")
            print(f"\n  Service Commands (on VPS):")
            print(f"    systemctl status msa")
            print(f"    journalctl -u msa -f")
            print(f"    systemctl restart msa")
        else:
            print("  DEPLOYMENT DONE (health check failed)")
            print(f"  SSH in to debug: ssh root@{VPS_HOST}")
            print(f"  Check logs: journalctl -u msa -f")
        print("=" * 55 + "\n")

    finally:
        client.close()
        print("[*] SSH connection closed.")


if __name__ == "__main__":
    main()
