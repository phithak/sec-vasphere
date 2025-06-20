import paramiko
import re

# === Configuration ===
OPENVAS_HOST = "192.168.20.103"
OPENVAS_USER = "prime-openvas"
OPENVAS_PASS = "Imegripe200408!"
SOCKET_PATH = "/run/gvmd/gvmd.sock"
GVM_USER = "admin"
GVM_PASS = "password"

# === SSH Helper ===
def ssh_exec(xml_cmd):
    cli_cmd = (
        f"gvm-cli --gmp-username {GVM_USER} --gmp-password {GVM_PASS} "
        f"socket --socketpath {SOCKET_PATH} --xml \"{xml_cmd}\""
    )
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(OPENVAS_HOST, username=OPENVAS_USER, password=OPENVAS_PASS)
    stdin, stdout, stderr = ssh.exec_command(cli_cmd)
    output = stdout.read().decode()
    error = stderr.read().decode()
    ssh.close()
    if error.strip():
        print(f"[⚠] STDERR: {error.strip()}")
    return output

def extract_ids(xml, tag):
    return re.findall(fr'<{tag} id="([a-f0-9\-]+)"', xml)

def cleanup_openvas():
    print("🚨 Cleaning up OpenVAS...")

    # 1. Delete all tasks
    tasks_xml = ssh_exec("<get_tasks details='1'/>")
    task_ids = extract_ids(tasks_xml, "task")
    print(f"[+] Found {len(task_ids)} task(s)")

    for task_id in task_ids:
        ssh_exec(f"<stop_task task_id='{task_id}'/>")
        ssh_exec(f"<delete_task task_id='{task_id}'/>")
        print(f"[✓] Deleted task {task_id}")

    # 2. Delete all reports
    reports_xml = ssh_exec("<get_reports/>")
    report_ids = extract_ids(reports_xml, "report")
    print(f"[+] Found {len(report_ids)} report(s)")

    for report_id in report_ids:
        ssh_exec(f"<delete_report report_id='{report_id}'/>")
        print(f"[✓] Deleted report {report_id}")

    # 3. Delete all targets
    targets_xml = ssh_exec("<get_targets/>")
    target_ids = extract_ids(targets_xml, "target")
    print(f"[+] Found {len(target_ids)} target(s)")

    for target_id in target_ids:
        result = ssh_exec(f"<delete_target target_id='{target_id}'/>")
        if 'status="200"' in result:
            print(f"[✓] Deleted target {target_id}")
        else:
            print(f"[✗] Failed to delete target {target_id} — possibly still in use")

    print("✅ OpenVAS cleanup complete.")

# === Run ===
if __name__ == "__main__":
    cleanup_openvas()

