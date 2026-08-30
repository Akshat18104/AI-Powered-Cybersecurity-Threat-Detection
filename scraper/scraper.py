import iocextract as ioc
import requests
import sqlite3 as sql
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'db', 'threat_log.db')

ABUSEIPDB_API_KEY = "a028236903014f3c9842ac1b4ef10a0ba42360259d4487fd6be35178841c8c4685d407a0ecb4476d"

def ip_reputation(ip_address):
    if not ABUSEIPDB_API_KEY:
        return "no api key"
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    try:
        response = requests.get(url, headers=headers, params = params, timeout = 5)
        if response.status_code == 200:
            score = response.json()["data"]["abuseConfidenceScore"]
            return f"{score}% Malicious Confidence"
    except Exception as e:
        print(f"[-] Threat feed lookup failed for {ip_address}: {e}")

    return "Lookup Error"

def process_threat_metadata(raw_metadata, source_type = "Email Header"):
    print(f"Analyzing {source_type}...")

    found_ips = list(set(ioc.extract_ips(raw_metadata)))
    found_urls = list(set(ioc.extract_urls(raw_metadata)))

    result =[]
    conn = sql.connect(DB_PATH)
    cursor = conn.cursor()

    for ip in found_ips:
        threat_status = ip_reputation(ip)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            "INSERT INTO logs (timestamp, payload, classification, source) VALUES (?, ?, ?, ?)",
            (current_time, ip, f"IP ({threat_status})", source_type)
        )
        result.append({"type":"IP", "value": ip, "status": threat_status})
    for url in found_urls:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
        "INSERT INTO logs (timestamp, payload, classification, source) VALUES (?, ?, ?, ?)",
        (current_time, url, "Extracted URL", source_type)
        )
        result.append({"type": "URL", "value": url, "status": "Extracted"})    

    conn.commit()
    conn.close()
    return result


if __name__ == "__main__":
    sample_text = "Received from mail server at 192.168.1.1 and 185.220.101.5"
    extracted = process_threat_metadata(sample_text)
    print(f"Complete. Found and logged: {extracted}")

