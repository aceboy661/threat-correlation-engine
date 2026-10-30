# Threat Correlation Engine
# Correlates authentication, process, and network logs

from datetime import datetime

def load_log(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        return []

def correlate_threats():
    auth_logs = load_log("logs/auth.log")
    process_logs = load_log("logs/process.log")
    network_logs = load_log("logs/network.log")

    print("=" * 60)
    print("THREAT CORRELATION ENGINE REPORT")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Failed logins
    failed_logins = [line for line in auth_logs if "Failed password" in line]
    print(f"\n[+] Failed Login Events: {len(failed_logins)}")
    for line in failed_logins:
        print(f"  - {line}")

    # Suspicious processes
    suspicious_processes = [line for line in process_logs if "/tmp/" in line or "/dev/shm/" in line]
    print(f"\n[+] Suspicious Process Events: {len(suspicious_processes)}")
    for line in suspicious_processes:
        print(f"  - {line}")

    # Unusual network ports
    unusual_ports = ["4444", "12345", "5555", "6666"]
    suspicious_network = []
    for line in network_logs:
        for port in unusual_ports:
            if f":{port}" in line:
                suspicious_network.append(line)
                break
    print(f"\n[+] Suspicious Network Events: {len(suspicious_network)}")
    for line in suspicious_network:
        print(f"  - {line}")

    # Correlation
    print("\n" + "-" * 60)
    print("CORRELATION ANALYSIS")
    print("-" * 60)

    score = 0
    if len(failed_logins) >= 3:
        score += 1
        print("• Multiple failed logins detected")
    if len(suspicious_processes) >= 1:
        score += 1
        print("• Suspicious process execution detected")
    if len(suspicious_network) >= 1:
        score += 1
        print("• Unusual network port activity detected")

    print(f"\nCorrelation Score: {score}/3")

    if score >= 2:
        print("\nALERT: High-confidence threat pattern detected!")
        print("Recommendation: Investigate source IPs, terminate suspicious processes, and review affected hosts.")
    elif score == 1:
        print("\nStatus: Single signal detected. Monitor for additional activity.")
    else:
        print("\nStatus: No significant correlated threats found.")

    print("=" * 60)

correlate_threats()
