import os
import time
import yaml
import paramiko
import socket
import re
import base64
import csv
from datetime import datetime
import threading
import time

# === Configuration ===
VICTIM_IP = "192.168.20.117"
VICTIM_USER = "root"
PRIVATE_KEY_PATH = "/root/.ssh/id_rsa"

OPENVAS_IP = "192.168.20.169"
OPENVAS_USER = "root"
OPENVAS_SSH_USER = "prime-openvas"
SOCKET_PATH = "/run/gvmd/gvmd.sock"

TARGET_LIST_FILE = "targets.yaml"

def inject_sudo_user_to_image(qcow2_path, vm_ip, vm_user):
    """
    Injects a sudo-enabled user 'prime' (password 'prime') into the image using virt-customize over SSH.
    Always tries both /etc/sudoers and /etc/sudoers.d/prime methods for maximum compatibility.
    """
    virt_customize_cmd = (
        f"virt-customize -a {qcow2_path} "
        "--run-command 'useradd -m -s /bin/bash prime || true' "
        "--run-command 'echo \"prime:prime\" | chpasswd' "
        "--run-command 'usermod -aG sudo prime || true' "
        
        "--run-command 'echo \"prime ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/prime' "
        "--run-command 'chmod 0440 /etc/sudoers.d/prime' "
        "--run-command 'rm -f /etc/sudoers.d/README || true' "
        "--run-command 'echo \"prime ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers || true' "
        "--run-command 'chmod 0440 /etc/sudoers || true' "
        
        "--run-command 'echo -e \"[Match]\\nName=eth*\\n[Network]\\nDHCP=yes\" > /etc/systemd/network/99-dhcp-all-eth.network || true' "
        "--run-command 'systemctl enable systemd-networkd || true' "
        "--run-command 'echo \"dhclient -v\" >> /etc/rc.local || true' "
        "--run-command 'chmod +x /etc/rc.local || true' "
        "--run-command 'rm -f /etc/udev/rules.d/70-persistent-net.rules || true' "
        "--run-command 'ln -sf /dev/null /etc/udev/rules.d/80-net-setup-link.rules || true' "

        "--run-command 'which apt-get && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server || true' "
        "--run-command 'which yum && yum install -y openssh-server || true' "
        "--run-command 'which dnf && dnf install -y openssh-server || true' "
        "--run-command 'which zypper && zypper -n install openssh || true' "
        "--run-command 'which apk && apk add openssh || true' "
        "--run-command 'mkdir -p /var/run/sshd || true' "
        
        "--run-command 'sed -i \"s/^#\\?PasswordAuthentication .*/PasswordAuthentication yes/\" /etc/ssh/sshd_config || echo \"PasswordAuthentication yes\" >> /etc/ssh/sshd_config' "
        "--run-command 'sed -i \"s/^#\\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/\" /etc/ssh/sshd_config || echo \"ChallengeResponseAuthentication no\" >> /etc/ssh/sshd_config' "
        "--run-command 'sed -i \"s/^#\\?UsePAM .*/UsePAM yes/\" /etc/ssh/sshd_config || echo \"UsePAM yes\" >> /etc/ssh/sshd_config' "
        "--run-command 'sed -i \"s/^#\\?PermitRootLogin .*/PermitRootLogin yes/\" /etc/ssh/sshd_config || echo \"PermitRootLogin yes\" >> /etc/ssh/sshd_config' "
        
        "--run-command 'systemctl enable ssh || systemctl enable sshd || true' "
        "--run-command 'systemctl restart ssh || systemctl restart sshd || service ssh restart || service sshd restart || true' "
        "--run-command 'service ssh start || service sshd start || true' "
    )
    print(f"[+] Injecting sudo user and network fixes via virt-customize: {virt_customize_cmd}")
    ssh_command(vm_ip, vm_user, virt_customize_cmd)

# --- Shared Workspace Paths ---
SHARE_ROOT = "/home/openvas_workspace"
OPENVAS_DIR = os.path.join(SHARE_ROOT, "openvas")
TARGET_DIR = os.path.join(SHARE_ROOT, "target")

def get_log_paths(vm, max_checks):
    """Returns tuple of openvas_log, target_log, scan_status for this scan."""
    openvas_log = os.path.join(OPENVAS_DIR, f"{vm}_maxchecks{max_checks}_openvas_resource_log.csv")
    target_log = os.path.join(TARGET_DIR, f"{vm}_maxchecks{max_checks}_target_resource_log.csv")
    scan_status = os.path.join(OPENVAS_DIR, f"{vm}_maxchecks{max_checks}_scan_status.txt")
    return openvas_log, target_log, scan_status

def clear_log_file(path):
    with open(path, "w") as f:
        f.truncate(0)

def wait_for_scan_completion(status_file, poll_interval=5):
    """Polls the status file for <status>Done</status>, waiting indefinitely."""
    while True:
        try:
            with open(status_file, "r") as f:
                content = f.read()
            if "<status>Done</status>" in content:
                print("[✓] Scan completed (status file)!")
                break
        except Exception as e:
            print(f"[!] Could not read status file yet: {e}")
        print("[*] Waiting for scan to complete...")
        time.sleep(poll_interval)
        
def start_resource_logger_on_vm(vm_ip, user, script_path, logfile_path, interface, scan_status_file, session_name):
    # Kill any previous logger in this session
    ssh_command(vm_ip, user, f"screen -S {session_name} -X quit || true")
    # Start new logger (uses SAR + scan status/progress if provided)
    cmd = f"screen -dmS {session_name} bash {script_path} {logfile_path} {interface} {scan_status_file}"
    ssh_command(vm_ip, user, cmd)
    print(f"[+] Started resource logger '{session_name}' on {vm_ip} logging to {logfile_path} with status from {scan_status_file}")

def stop_resource_logger_on_vm(vm_ip, user, session_name):
    ssh_command(vm_ip, user, f"screen -S {session_name} -X quit || true")
    print(f"[+] Stopped resource logger '{session_name}' on {vm_ip}")
    
def start_status_logger_on_vm(vm_ip, user, script_path, task_id, status_file, session_name):
    # Kill any previous logger with this session
    ssh_command(vm_ip, user, f"screen -S {session_name} -X quit || true")
    # Start status logger as prime-openvas for the given task_id (login shell!)
    cmd = (
        f"screen -dmS {session_name} "
        f"sudo -iu prime-openvas /bin/bash {script_path} {task_id} {status_file}"
    )
    ssh_command(vm_ip, user, cmd)
    print(f"[+] Started status logger '{session_name}' as prime-openvas for task {task_id} on {vm_ip} to {status_file}")

def stop_status_logger_on_vm(vm_ip, user, session_name):
    ssh_command(vm_ip, user, f"screen -S {session_name} -X quit || true")
    print(f"[+] Stopped status logger '{session_name}' on {vm_ip}")

def tail_file(filepath, stop_event, label=""):
    """
    Print new lines appended to filepath as they appear.
    """
    try:
        with open(filepath, "r") as f:
            f.seek(0, os.SEEK_END)  # Move to the end (skip header and past lines)
            while not stop_event.is_set():
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                print(f"[{label}] {line.strip()}")
    except Exception as e:
        print(f"[TAIL:{label}] Error tailing {filepath}: {e}")

def tail_remote_file(vm_ip, user, remote_path, stop_event):
    """
    Tails a remote file over SSH, printing new lines as they appear.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.RSAKey.from_private_key_file(PRIVATE_KEY_PATH)
    ssh.connect(hostname=vm_ip, username=user, pkey=key)
    transport = ssh.get_transport()
    channel = transport.open_session()
    channel.exec_command(f"tail -n 20 -f {remote_path}")
    try:
        while not stop_event.is_set():
            if channel.recv_ready():
                line = channel.recv(4096).decode()
                print(f"[WGET] {line}", end="")
            time.sleep(0.5)
    finally:
        channel.close()
        ssh.close()

# === SSH Helper ===
def ssh_command(host, username, command, password=None):
    print(f"[SSH:{host}] ➔ {command}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if password:
        ssh.connect(hostname=host, username=username, password=password)
    else:
        key = paramiko.RSAKey.from_private_key_file(PRIVATE_KEY_PATH)
        ssh.connect(hostname=host, username=username, pkey=key)
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()
    ssh.close()
    if error.strip():
        print(f"[SSH:{host}] ⚠ STDERR: {error.strip()}")
    return output.strip()
    
def get_or_create_ssh_credential(username, password):
    # First, try to find an existing credential
    xml = ssh_openvas_cmd("<get_credentials/>")
    for cred in re.findall(r'(<credential id="[^"]+".*?</credential>)', xml, re.DOTALL):
        if f"<name>SSH-{username}</name>" in cred:
            match = re.search(r'id="([a-f0-9\-]+)"', cred)
            if match:
                cred_id = match.group(1)
                print(f"[OpenVAS] Found existing SSH credential id: {cred_id}")
                return cred_id
    # Otherwise, create a new one
    xml_create = (
        "<create_credential>"
        f"<name>SSH-{username}</name>"
        f"<login>{username}</login>"
        "<authentication>password</authentication>"
        f"<password>{password}</password>"
        "</create_credential>"
    )
    resp = ssh_openvas_cmd(xml_create)
    cred_id = extract_id(resp)
    if not cred_id:
        raise Exception(f"Failed to create SSH credential for {username}")
    print(f"[OpenVAS] Created SSH credential id: {cred_id}")
    return cred_id

# === OpenVAS Helpers ===
def ssh_openvas_cmd(xml_cmd):
    print(f"[OpenVAS] XML CMD: {xml_cmd}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(OPENVAS_IP, username=OPENVAS_SSH_USER, password="Imegripe200408!")
    cmd = f"gvm-cli --gmp-username admin --gmp-password password socket --socketpath {SOCKET_PATH} --xml \"{xml_cmd}\""
    stdin, stdout, stderr = ssh.exec_command(cmd)
    output = stdout.read().decode()
    error = stderr.read().decode()
    ssh.close()
    if error.strip():
        print(f"[OpenVAS:ERROR] {error.strip()}")
    return output.strip()

def extract_id(xml, match=None):
    pattern = r'id="([a-f0-9\-]+)"'
    matches = re.findall(pattern, xml)
    if not matches:
        return None
    if match:
        for line in xml.splitlines():
            if match.lower() in line.lower():
                match_id = re.search(pattern, line)
                if match_id:
                    return match_id.group(1)
        return None
    return matches[0]

def extract_report_format_id(report_type):
    xml = ssh_openvas_cmd("<get_report_formats/>")
    format_blocks = re.findall(r'(<report_format .*?</report_format>)', xml, re.DOTALL)
    for block in format_blocks:
        # For PDF
        if report_type.lower() == "pdf" and (
            re.search(r'<extension>\s*pdf\s*</extension>', block, re.I) or
            re.search(r'<content_type>\s*application/pdf\s*</content_type>', block, re.I)
        ):
            match = re.search(r'id="([a-f0-9\-]+)"', block)
            if match:
                return match.group(1)
        # For XML
        if report_type.lower() == "xml" and (
            re.search(r'<extension>\s*xml\s*</extension>', block, re.I) or
            re.search(r'<content_type>\s*text/xml\s*</content_type>', block, re.I)
        ):
            match = re.search(r'id="([a-f0-9\-]+)"', block)
            if match:
                return match.group(1)
    return None

def extract_base64_report_content(raw_output):
    match = re.search(r"</report_format>(.*?)</report>", raw_output, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None

def get_full_and_fast_config_id():
    configs_xml = ssh_openvas_cmd("<get_configs/>")
    config_blocks = re.findall(r'(<config id="[^"]+".*?</config>)', configs_xml, re.DOTALL)
    for block in config_blocks:
        if re.search(r'<name>\s*Full and fast\s*</name>', block, re.IGNORECASE):
            match = re.search(r'<config id="([a-f0-9\-]+)"', block)
            if match:
                return match.group(1)
    raise Exception("Could not find 'Full and fast' config ID in OpenVAS.")

def get_port_list_id(preferred_name="All IANA assigned TCP and UDP"):
    xml = ssh_openvas_cmd("<get_port_lists/>")
    port_blocks = re.findall(r'(<port_list id="[^"]+".*?</port_list>)', xml, re.DOTALL)
    for block in port_blocks:
        if re.search(rf'<name>\s*{re.escape(preferred_name)}\s*</name>', block, re.I):
            match = re.search(r'<port_list id="([a-f0-9\-]+)"', block)
            if match:
                return match.group(1)
    match = re.search(r'<port_list id="([a-f0-9\-]+)"', xml)
    if match:
        return match.group(1)
    return None

# === VM Setup and Control ===
def download_image_and_define_vm(target):
    name = target["name"]
    url = target["image_url"]
    memory = target.get("memory", 1024)
    vcpus = target.get("vcpus", 1)
    base_path = f"/var/lib/libvirt/images/{name}"

    filename_from_url = url.split("/")[-1]
    download_path = f"{base_path}_{filename_from_url}"
    wget_log = f"{download_path}.wgetlog"

    print(f"[+] Downloading {url} to {download_path} on victim VM...")

    # Start tailing the wget log file before starting download
    stop_wget_tail = threading.Event()
    wget_tail_thread = threading.Thread(
        target=tail_remote_file,
        args=(VICTIM_IP, VICTIM_USER, wget_log, stop_wget_tail),
        daemon=True
    )
    wget_tail_thread.start()

    # Start wget with progress
    download_cmd = f"wget --progress=dot:mega -O {download_path} {url} 2>&1 | tee {wget_log}"
    ssh_command(VICTIM_IP, VICTIM_USER, download_cmd)

    # Stop the tail after download finishes
    stop_wget_tail.set()
    wget_tail_thread.join(timeout=2)

    qcow2_path = extract_qcow2_if_needed(download_path, name)
    inject_sudo_user_to_image(qcow2_path, VICTIM_IP, VICTIM_USER)
    print(f"[+] Defining VM {name} using virt-install with br0...")
    ssh_command(VICTIM_IP, VICTIM_USER,
        f"virt-install --name {name} --memory {memory} --vcpus {vcpus} "
        f"--disk path={qcow2_path},format=qcow2,size=8 --os-variant=generic "
        f"--import --noautoconsole --network bridge=br0")

def extract_qcow2_if_needed(filename, vm_name):
    qcow2_path = f"/var/lib/libvirt/images/{vm_name}.qcow2"
    extract_dir = f"/tmp/{vm_name}_extract"

    print(f"[+] Checking file type of {filename}...")
    if filename.endswith(".qcow2"):
        ssh_command(VICTIM_IP, VICTIM_USER, f"cp {filename} {qcow2_path}")
    elif filename.endswith(".iso") or filename.endswith(".img"):
        print(f"[+] Converting ISO/IMG to QCOW2...")
        ssh_command(VICTIM_IP, VICTIM_USER, f"qemu-img convert -f raw -O qcow2 {filename} {qcow2_path}")
    elif filename.endswith(".vmdk"):
        print(f"[+] Converting VMDK to QCOW2...")
        ssh_command(VICTIM_IP, VICTIM_USER, f"qemu-img convert -f vmdk -O qcow2 {filename} {qcow2_path}")
    elif filename.endswith(".ova"):
        print(f"[+] Extracting OVA file...")
        ssh_command(VICTIM_IP, VICTIM_USER, f"mkdir -p {extract_dir}")
        ssh_command(VICTIM_IP, VICTIM_USER, f"tar -xf {filename} -C {extract_dir}")
        vmdk = ssh_command(VICTIM_IP, VICTIM_USER, f"find {extract_dir} -name '*.vmdk' | head -n 1")
        if vmdk:
            print(f"[+] Converting extracted VMDK to QCOW2...")
            ssh_command(VICTIM_IP, VICTIM_USER, f"qemu-img convert -f vmdk -O qcow2 {vmdk} {qcow2_path}")
        else:
            raise Exception("[✗] No VMDK found in extracted OVA")
    elif filename.endswith(".zip"):
        print(f"[+] Extracting ZIP file...")
        ssh_command(VICTIM_IP, VICTIM_USER, f"mkdir -p {extract_dir}")
        ssh_command(VICTIM_IP, VICTIM_USER, f"unzip -o {filename} -d {extract_dir} || true")
        # Now look for .ova, .qcow2, .vmdk, .img, .iso inside extracted folder
        ova = ssh_command(VICTIM_IP, VICTIM_USER, f"find {extract_dir} -name '*.ova' | head -n 1")
        if ova:
            print(f"[+] Found OVA inside ZIP, extracting OVA...")
            ssh_command(VICTIM_IP, VICTIM_USER, f"tar -xf {ova} -C {extract_dir}")
            vmdk = ssh_command(VICTIM_IP, VICTIM_USER, f"find {extract_dir} -name '*.vmdk' | head -n 1")
            if vmdk:
                ssh_command(VICTIM_IP, VICTIM_USER, f"qemu-img convert -f vmdk -O qcow2 {vmdk} {qcow2_path}")
            else:
                raise Exception("[✗] No VMDK found in extracted OVA inside ZIP")
        else:
            # fallback to qcow2, vmdk, iso, img
            qcow2 = ssh_command(VICTIM_IP, VICTIM_USER, f"find {extract_dir} -name '*.qcow2' | head -n 1")
            if qcow2:
                ssh_command(VICTIM_IP, VICTIM_USER, f"cp {qcow2} {qcow2_path}")
            else:
                vmdk = ssh_command(VICTIM_IP, VICTIM_USER, f"find {extract_dir} -name '*.vmdk' | head -n 1")
                if vmdk:
                    ssh_command(VICTIM_IP, VICTIM_USER, f"qemu-img convert -f vmdk -O qcow2 {vmdk} {qcow2_path}")
                else:
                    iso = ssh_command(VICTIM_IP, VICTIM_USER, f"find {extract_dir} -name '*.iso' | head -n 1")
                    if iso:
                        ssh_command(VICTIM_IP, VICTIM_USER, f"qemu-img convert -f raw -O qcow2 {iso} {qcow2_path}")
                    else:
                        raise Exception("[✗] No usable image found (.qcow2, .vmdk, .iso, .img, .ova) in extracted ZIP")
    else:
        print(f"[+] Attempting to extract archive...")
        ssh_command(VICTIM_IP, VICTIM_USER, f"mkdir -p {extract_dir}")
        ssh_command(VICTIM_IP, VICTIM_USER, f"unzip -o {filename} -d {extract_dir} || true")
        ssh_command(VICTIM_IP, VICTIM_USER, f"tar -xf {filename} -C {extract_dir} || true")
        qcow2 = ssh_command(VICTIM_IP, VICTIM_USER, f"find {extract_dir} -name '*.qcow2' | head -n 1")
        if qcow2:
            ssh_command(VICTIM_IP, VICTIM_USER, f"cp {qcow2} {qcow2_path}")
        else:
            vmdk = ssh_command(VICTIM_IP, VICTIM_USER, f"find {extract_dir} -name '*.vmdk' | head -n 1")
            if vmdk:
                ssh_command(VICTIM_IP, VICTIM_USER, f"qemu-img convert -f vmdk -O qcow2 {vmdk} {qcow2_path}")
            else:
                raise Exception("[✗] No usable image found (.qcow2, .vmdk, .iso, .img, .ova)")
    verify = ssh_command(VICTIM_IP, VICTIM_USER, f"ls {qcow2_path} || echo 'MISSING'")
    if "MISSING" in verify:
        raise Exception(f"[✗] Failed to prepare .qcow2 image at {qcow2_path}")
    return qcow2_path

def get_vm_mac(vm_name):
    raw_mac = ssh_command(VICTIM_IP, VICTIM_USER, f"virsh domiflist {vm_name} | awk '/br0/ {{print $5}}'")
    return raw_mac.strip().upper()

def find_ip_by_mac(mac):
    for _ in range(30):
        print(f"[+] Scanning for MAC {mac} with nmap...")
        cmd = (
            "sudo nmap -sn 192.168.20.0/24 | awk '"
            "/Nmap scan report/ {ip=$NF} "
            f"/MAC Address/ {{mac=toupper($3); if(mac==\"{mac}\") print ip}}'"
        )
        ip = ssh_command(VICTIM_IP, VICTIM_USER, cmd)
        print(f"[NMAP OUTPUT] ➔ {ip}")
        if ip and test_ssh_port(ip):
            print(f"[✓] Found IP for MAC {mac}: {ip.strip()}")
            return ip.strip()
        time.sleep(3)
    raise Exception("[\u2717] Could not determine IP address for VM")

def test_ssh_port(ip):
    try:
        sock = socket.create_connection((ip, 22), timeout=3)
        sock.close()
        return True
    except:
        return False

def destroy_vm(name):
    print(f"[+] Destroying VM {name}")
    ssh_command(VICTIM_IP, VICTIM_USER, f"virsh destroy {name} || true")
    ssh_command(VICTIM_IP, VICTIM_USER, f"virsh undefine {name} || true")

# === Scan Execution ===
def target_exists(target_name):
    """Return True if a target by name exists in OpenVAS."""
    targets_xml = ssh_openvas_cmd("<get_targets/>")
    return f">{target_name}<" in targets_xml

def get_next_available_target_name(base_name):
    """Generate a unique target name by incrementing suffix."""
    if not target_exists(base_name):
        return base_name
    suffix = 1
    while True:
        candidate = f"{base_name}_{suffix}"
        if not target_exists(candidate):
            return candidate
        suffix += 1

def create_new_target(name, ip, credential_id=None):
    port_list_id = get_port_list_id("All IANA assigned TCP and UDP")
    if not port_list_id:
        raise Exception("[✗] No valid port list found.")
    print(f"[OpenVAS] Creating new target '{name}'...")
    cred_xml = f"<ssh_credential id='{credential_id}'/>" if credential_id else ""
    xml = (
        f"<create_target>"
        f"<name>{name}</name>"
        f"<hosts>{ip}</hosts>"
        f"<port_list id='{port_list_id}'/>"
        f"{cred_xml}"
        f"</create_target>"
    )
    target_xml = ssh_openvas_cmd(xml)
    target_id = extract_id(target_xml)
    if not target_id:
        raise Exception(f"[✗] Failed to create target '{name}'")
    return target_id

def start_scan(target_id, vm_name, max_checks):
    config_id = get_full_and_fast_config_id()
    print(f"[OpenVAS] Creating task for target image with config 'Full and fast' (id={config_id}), max_checks={max_checks}...")
    xml_task = (
        f"<create_task>"
        f"<name>{vm_name}_scan_maxchecks_{max_checks}</name>"
        f"<config id='{config_id}'/>"
        f"<target id='{target_id}'/>"
        f"<preferences>"
        f"<preference><scanner_name>max_hosts</scanner_name><value>1</value></preference>"
        f"<preference><scanner_name>max_checks</scanner_name><value>{max_checks}</value></preference>"
        f"</preferences>"
        f"</create_task>"
    )
    print("[DEBUG] XML to send:\n", xml_task)
    task_xml = ssh_openvas_cmd(xml_task)
    task_id = extract_id(task_xml)
    if not task_id:
        raise Exception("[✗] Failed to create scan task")
    print(f"[OpenVAS] Starting scan task ID: {task_id}")
    ssh_openvas_cmd(f"<start_task task_id='{task_id}'/>")
    return task_id

def save_report(filename, content):
    with open(filename, "w") as f:
        f.write(content)
    os.chmod(filename, 0o644)

def download_reports(report_id, vm_name, max_checks):
    for label, ext in [("pdf", "pdf"), ("xml", "xml")]:
        fmt_id = extract_report_format_id(label)
        if not fmt_id:
            print(f"[✗] Report format '{label}' not found.")
            continue
        print(f"[OpenVAS] Downloading {label.upper()} report...")
        if label == "pdf":
            xml_cmd = (
                f"<get_reports report_id='{report_id}' "
                f"format_id='{fmt_id}' "
                f"filter='apply_overrides=0 levels=hmlg min_qod=50 first=1 rows=1000 sort=name ignore_pagination=1' "
                f"details='1'/>"
            )
        else:
            xml_cmd = f"<get_reports report_id='{report_id}' format_id='{fmt_id}'/>"
        raw_output = ssh_openvas_cmd(xml_cmd)
        filename = f"{vm_name}_maxchecks{max_checks}_report.{ext}"
        try:
            if label == "pdf":
                base64_data = extract_base64_report_content(raw_output)
                if not base64_data:
                    print(f"[x] Failed to extract {label.upper()} report content.")
                    continue
                b64_filename = f"{vm_name}_maxchecks{max_checks}_report_base64.b64"
                try:
                    with open(b64_filename, "w") as b64_file:
                        b64_file.write(base64_data)
                    print(f"[✓] Saved raw base64 report to {b64_filename}")
                except Exception as e:
                    print(f"[x] Failed to save raw base64 report: {e}")
                try:
                    decoded = base64.b64decode(base64_data, validate=True)
                    with open(filename, "wb") as f:
                        f.write(decoded)
                    print(f"[✓] Saved {filename}")
                except Exception as e:
                    print(f"[✗] Failed to decode PDF: {e}")
                    continue
            else:
                with open(filename, "w") as f:
                    f.write(raw_output)
                print(f"[✓] Saved {filename}")
        except Exception as e:
            print(f"[✗] Failed to save {label.upper()}: {e}")

def load_targets():
    with open(TARGET_LIST_FILE, "r") as f:
        return yaml.safe_load(f)

def main():
    targets = load_targets()
    ssh_cred_id = get_or_create_ssh_credential("prime", "prime")
    for target in targets:
        vm = target["name"]
        try:
            print(f"\n=== Processing Target: {vm} ===")
            download_image_and_define_vm(target)
            print("[*] Waiting 100s for VM to boot...")
            time.sleep(100)
            mac = get_vm_mac(vm)
            ip = find_ip_by_mac(mac)
            unique_target_name = get_next_available_target_name(vm)
            target_id = create_new_target(unique_target_name, ip, credential_id=ssh_cred_id)
            for max_checks in [1, 2, 3, 4]:
                print(f"\n[===] Starting scan for max_checks={max_checks} [===]")
                openvas_log, target_log, scan_status = get_log_paths(vm, max_checks)
                clear_log_file(openvas_log)
                clear_log_file(target_log)
            
                precreate_status_cmd = (
                    f"touch {scan_status} && chown prime-openvas:prime-openvas {scan_status} && chmod 644 {scan_status}"
                )
                ssh_command(OPENVAS_IP, OPENVAS_USER, precreate_status_cmd)

                # --- Unique screen session names for each run
                openvas_logger_session = f"openvas_logger_{vm}_maxchecks{max_checks}"
                victim_logger_session = f"victim_logger_{vm}_maxchecks{max_checks}"

                # Start resource loggers
                start_resource_logger_on_vm(
                    OPENVAS_IP, OPENVAS_USER,
                    "/home/openvas_workspace/openvas/resource_logger.sh",
                    openvas_log, "eth0", scan_status, openvas_logger_session
                )
                start_resource_logger_on_vm(
                    VICTIM_IP, VICTIM_USER,
                    "/home/openvas_workspace/target/resource_logger.sh",
                    target_log, "br0", scan_status, victim_logger_session
                )

                # --- Start tailing logs for debugging
                openvas_tail_stop = threading.Event()
                victim_tail_stop = threading.Event()
                openvas_tail_thread = threading.Thread(target=tail_file, args=(openvas_log, openvas_tail_stop, "OPENVAS"))
                victim_tail_thread = threading.Thread(target=tail_file, args=(target_log, victim_tail_stop, "VICTIM"))
                openvas_tail_thread.start()
                victim_tail_thread.start()

                time.sleep(5)
                scan_task_id = start_scan(target_id, vm, max_checks)

                # Unique status logger session name
                status_logger_session = f"status_logger_{vm}_maxchecks{max_checks}"

                # --- Start scan status logger (runs on OpenVAS VM, as prime-openvas)
                start_status_logger_on_vm(
                    OPENVAS_IP, OPENVAS_USER,
                    "/home/openvas_workspace/openvas/scan_status_logger.sh",
                    scan_task_id, scan_status, status_logger_session
                )

                try:
                    wait_for_scan_completion(scan_status, poll_interval=5)
                finally:
                    time.sleep(10)
                    # --- Stop all loggers even on error
                    stop_resource_logger_on_vm(OPENVAS_IP, OPENVAS_USER, openvas_logger_session)
                    stop_resource_logger_on_vm(VICTIM_IP, VICTIM_USER, victim_logger_session)
                    stop_status_logger_on_vm(OPENVAS_IP, OPENVAS_USER, status_logger_session)
                    # --- Stop tailing threads
                    openvas_tail_stop.set()
                    victim_tail_stop.set()
                    openvas_tail_thread.join()
                    victim_tail_thread.join()

                # --- After scan, download OpenVAS reports as before
                for _ in range(5):
                    task_status_xml = ssh_openvas_cmd(f"<get_tasks task_id='{scan_task_id}' details='1'/>")
                    report_id_match = re.search(r'<last_report>.*?<report id="([a-f0-9\-]+)"', task_status_xml, re.DOTALL)
                    if report_id_match:
                        report_id = report_id_match.group(1)
                        break
                    print("[!] Report not yet available, retrying...")
                    time.sleep(5)
                else:
                    raise Exception("[✗] Failed to get report ID after scan.")
                download_reports(report_id, vm, max_checks)
                print(f"[+] Finished scan for {vm} max_checks={max_checks}.")
        except Exception as e:
            print(f"[!] Exception occurred for {vm}: {e}")
        finally:
            destroy_vm(vm)


if __name__ == "__main__":
    main()

