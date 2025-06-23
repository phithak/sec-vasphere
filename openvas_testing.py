import os
import time
import yaml
import paramiko
import socket
import re
import base64

# === Configuration ===
VICTIM_IP = "192.168.20.117"
VICTIM_USER = "root"
PRIVATE_KEY_PATH = "/root/.ssh/id_rsa"

OPENVAS_IP = "192.168.20.103"
OPENVAS_SSH_USER = "prime-openvas"
SOCKET_PATH = "/run/gvmd/gvmd.sock"

TARGET_LIST_FILE = "targets.yaml"

# === SSH Helper ===
def ssh_command(host, username, command):
    print(f"[SSH:{host}] ➔ {command}")
    key = paramiko.RSAKey.from_private_key_file(PRIVATE_KEY_PATH)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=username, pkey=key)
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()
    ssh.close()
    if error.strip():
        print(f"[SSH:{host}] ⚠ STDERR: {error.strip()}")
    return output.strip()

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
    # Find all report_formats
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
    """
    Extract only the base64 content from the OpenVAS PDF report XML.
    Looks for content after the last </report_format> before </report>.
    """
    match = re.search(r"</report_format>(.*?)</report>", raw_output, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None
    
def get_full_and_fast_config_id():
    configs_xml = ssh_openvas_cmd("<get_configs/>")
    # Find all <config ...> ... </config> blocks
    config_blocks = re.findall(r'(<config id="[^"]+".*?</config>)', configs_xml, re.DOTALL)
    for block in config_blocks:
        # Look for the <name>Full and fast</name> in each block
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
    # fallback to the first port list as last resort
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

    # Extract filename from URL (preserve extension)
    filename_from_url = url.split("/")[-1]
    download_path = f"{base_path}_{filename_from_url}"  # e.g., /var/lib/libvirt/images/dvwa_1_0_7.iso

    print(f"[+] Downloading {url} to {download_path} on victim VM...")
    ssh_command(VICTIM_IP, VICTIM_USER, f"wget -O {download_path} {url}")

    # Pass correct filename with extension
    qcow2_path = extract_qcow2_if_needed(download_path, name)

    print(f"[+] Defining VM {name} using virt-install with br0...")
    ssh_command(VICTIM_IP, VICTIM_USER,
        f"virt-install --name {name} --memory {memory} --vcpus {vcpus} "
        f"--disk path={qcow2_path},format=qcow2,size=8 --os-variant=generic "
        f"--import --noautoconsole --network bridge=br0")

def extract_qcow2_if_needed(filename, vm_name):
    qcow2_path = f"/var/lib/libvirt/images/{vm_name}.qcow2"
    extract_dir = f"/tmp/{vm_name}_extract"

    print(f"[+] Checking file type of {filename}...")

    # Detect file extension
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
def get_or_create_target(name, ip):
    targets_xml = ssh_openvas_cmd("<get_targets/>")
    existing_id = None
    for line in targets_xml.splitlines():
        if f">{name}<" in line:
            existing_id = extract_id(line)
            print(f"[OpenVAS] Found existing target '{name}' with ID: {existing_id}")
            break

    if existing_id:
        tasks_xml = ssh_openvas_cmd("<get_tasks details='1'/>")
        for block in tasks_xml.split("<task>")[1:]:
            if existing_id in block:
                task_id = extract_id(block)
                status_match = re.search(r"<status>(.*?)</status>", block)
                status = status_match.group(1).lower() if status_match else ""
                if status in ["running", "paused", "interrupted"]:
                    print(f"[OpenVAS] Stopping task {task_id} (status: {status})...")
                    ssh_openvas_cmd(f"<stop_task task_id='{task_id}'/>")
                    time.sleep(3)
                print(f"[OpenVAS] Deleting task {task_id}...")
                ssh_openvas_cmd(f"<delete_task task_id='{task_id}'/>")
                time.sleep(1)

        reports_xml = ssh_openvas_cmd("<get_reports/>")
        for line in reports_xml.splitlines():
            if existing_id in line:
                report_id = extract_id(line)
                print(f"[OpenVAS] Deleting report {report_id}...")
                ssh_openvas_cmd(f"<delete_report report_id='{report_id}'/>")
                time.sleep(1)

        # Retry deletion up to 5 times
        for _ in range(5):
            result = ssh_openvas_cmd(f"<delete_target target_id='{existing_id}'/>")
            if "status=\"200\"" in result:
                print(f"[✓] Successfully deleted target '{name}'")
                existing_id = None
                break
            else:
                print("[!] Target still in use, retrying...")
                time.sleep(2)

    # Continue using existing if deletion failed
    if existing_id:
        print(f"[!] Using existing target ID: {existing_id}")
        return existing_id

    # Create new target
    port_list_id = get_port_list_id("All IANA assigned TCP and UDP")
    if not port_list_id:
        raise Exception("[✗] No valid port list found.")

    print(f"[OpenVAS] Creating new target '{name}'...")
    target_xml = ssh_openvas_cmd(f"<create_target><name>{name}</name><hosts>{ip}</hosts><port_list id='{port_list_id}'/></create_target>")
    target_id = extract_id(target_xml)
    if not target_id:
        raise Exception(f"[✗] Failed to create target '{name}'")
    return target_id

def start_scan(target_id):
    config_id = get_full_and_fast_config_id()
    print(f"[OpenVAS] Creating task for target image with config 'Full and fast' (id={config_id})...")
    task_xml = ssh_openvas_cmd(
        f"<create_task><name>image_scan</name><config id='{config_id}'/><target id='{target_id}'/></create_task>"
    )
    task_id = extract_id(task_xml)
    if not task_id:
        raise Exception("[✗] Failed to create scan task")

    print(f"[OpenVAS] Starting scan task ID: {task_id}")
    ssh_openvas_cmd(f"<start_task task_id='{task_id}'/>")

    # Infinite poll until scan completes
    waited = 0
    poll_interval = 10
    while True:
        task_status_xml = ssh_openvas_cmd(f"<get_tasks task_id='{task_id}' details='1'/>")
        print(task_status_xml)
        if "<status>Done</status>" in task_status_xml:
            print("[✓] Scan completed.")
            break
        print(f"[*] Waiting for scan to finish... {waited//60} min elapsed")
        time.sleep(poll_interval)
        waited += poll_interval

    # Retry fetching report ID after scan is marked as Done
    for _ in range(5):
        task_status_xml = ssh_openvas_cmd(f"<get_tasks task_id='{task_id}' details='1'/>")
        report_id_match = re.search(r'<last_report>.*?<report id="([a-f0-9\-]+)"', task_status_xml, re.DOTALL)
        if report_id_match:
            report_id = report_id_match.group(1)
            return report_id
        print("[!] Report not yet available, retrying...")
        time.sleep(5)

    raise Exception("[✗] Failed to get report ID after scan.")

def save_report(filename, content):
    with open(filename, "w") as f:
        f.write(content)
    os.chmod(filename, 0o644)

def download_reports(report_id, vm_name):
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
                f"filter='apply_overrides=0 levels=hml min_qod=50 first=1 rows=1000 sort=name ignore_pagination=1' "
                f"details='1'/>"
            )
        else:
            xml_cmd = f"<get_reports report_id='{report_id}' format_id='{fmt_id}'/>"
        raw_output = ssh_openvas_cmd(xml_cmd)

        filename = f"{vm_name}_report.{ext}"
        try:
            if label == "pdf":
                base64_data = extract_base64_report_content(raw_output)
                if not base64_data:
                    print(f"[x] Failed to extract {label.upper()} report content.")
                    continue

                # Save raw base64 for debugging
                b64_filename = f"{vm_name}_report_base64.b64"
                try:
                    with open(b64_filename, "w") as b64_file:
                        b64_file.write(base64_data)
                    print(f"[✓] Saved raw base64 report to {b64_filename}")
                except Exception as e:
                    print(f"[x] Failed to save raw base64 report: {e}")

                # Try decoding
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

# === Main ===
def load_targets():
    with open(TARGET_LIST_FILE, "r") as f:
        return yaml.safe_load(f)

def main():
    targets = load_targets()
    for target in targets:
        vm = target["name"]
        try:
            print(f"\n=== 🚀 Processing Target: {vm} ===")
            download_image_and_define_vm(target)
            print("[*] Waiting 60s for VM to boot...")
            time.sleep(60)
            mac = get_vm_mac(vm)
            ip = find_ip_by_mac(mac)
            target_id = get_or_create_target(vm, ip)
            report_id = start_scan(target_id)
            download_reports(report_id, vm)
        except Exception as e:
            print(f"[!] Exception occurred for {vm}: {e}")
        finally:
            destroy_vm(vm)

if __name__ == "__main__":
    main()
