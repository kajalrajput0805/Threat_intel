# === FINAL THREAT ENRICHMENT SCRIPT WITH OTX → VT → THREATMINER FALLBACK (UPDATED INDICATOR STORAGE) ===

import requests
import psycopg2
import ipaddress
import time
from datetime import datetime
import sys
import os
import logging
import re

from dotenv import load_dotenv
load_dotenv()
# ========== LOGGING ==========
logging.basicConfig(filename='fetch_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')
print("=== Threat Intel Script Started ===")
print("Python Path:", sys.executable)
print("Working Directory:", os.getcwd())

# ========== CONFIG ==========
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ZOOMEYE_API_KEY = os.getenv("ZOOMEYE_API_KEY")


SUBSCRIBED_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed?page={}"
HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}

# ========== DB CONNECTION ==========
conn = psycopg2.connect(
    host=os.getenv("DB_HOST"),
    dbname=os.getenv("DB_NAME"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD")
)
cursor = conn.cursor()

# ========== HELPERS ==========
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def classify_hash_type(value):
    value = value.strip().lower()
    if re.fullmatch(r"[a-f0-9]{32}", value): return "MD5"
    elif re.fullmatch(r"[a-f0-9]{40}", value): return "SHA1"
    elif re.fullmatch(r"[a-f0-9]{64}", value): return "SHA256"
    elif re.fullmatch(r"[a-f0-9]{128}", value): return "SHA512"
    return "HASH"

# ========== ENRICHMENT ==========
def enrich_ipinfo(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}")
        d = r.json()
        country_code = d.get('country', '')
        country = ''
        if country_code:
            resp = requests.get(f"https://restcountries.com/v3.1/alpha/{country_code}")
            country = resp.json()[0]['name']['common'] if resp.status_code == 200 else country_code
        org = d.get('org', '')
        asn = org.split(' ')[0] if org.startswith('AS') else ''
        return country, d.get('city', ''), org, asn
    except Exception as e:
        logging.error(f"[IPINFO ERROR] {ip}: {e}")
        return '', '', '', ''

def enrich_shodan(ip):
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}")
        if r.status_code != 200: return ''
        data = r.json()
        return ', '.join(str(service['port']) for service in data.get('data', []))
    except: return ''

def enrich_zoomeye(ip):
    try:
        headers = {"Authorization": f"JWT {ZOOMEYE_API_KEY}"}
        r = requests.get(f"https://api.zoomeye.org/host/search?query={ip}", headers=headers, timeout=10)
        ports = {str(match.get('portinfo', {}).get('port')) for match in r.json().get('matches', []) if match.get('portinfo', {}).get('port')}
        return ', '.join(sorted(ports))
    except Exception as e:
        logging.error(f"[ZOOMEYE ERROR] {ip}: {e}")
        return ''

def enrich_ports(ip):
    ports = enrich_shodan(ip)
    return ports if ports else enrich_zoomeye(ip)

# ========== FETCHERS ==========
def fetch_abuseipdb_ips():
    try:
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        params = {'confidenceMinimum': 90, 'limit': 100}
        r = requests.get(url, headers=headers, params=params)
        return [item['ipAddress'] for item in r.json().get('data', [])]
    except Exception as e:
        logging.error(f"[ABUSEIPDB ERROR]: {e}")
        return []

def fetch_subscribed_otx_indicators(pages=3):
    seen_ips = set()
    all_records = []

    for page in range(1, pages + 1):
        try:
            r = requests.get(SUBSCRIBED_PULSES_URL.format(page), headers=HEADERS)
            if r.status_code != 200: continue
            data = r.json()
            for pulse in data.get("results", []):
                indicators = pulse.get("indicators", [])
                threat_actors = pulse.get("threat_hunting_tags", []) or []

                pulse_ips = [ind["indicator"] for ind in indicators if ind.get("type") == "IPv4" and is_valid_ip(ind["indicator"])]

                for ip in pulse_ips:
                    seen_ips.add(ip)
                    for ind in indicators:
                        i_value = ind.get("indicator", "").strip()
                        i_type = ind.get("type", "").upper()

                        if not i_value or i_value == ip:
                            continue

                        if i_type == "URL":
                            all_records.append((ip, i_value, "URL"))
                        elif i_type == "DOMAIN":
                            all_records.append((ip, i_value, "DOMAIN"))
                        elif i_type.startswith("FILEHASH"):
                            htype = classify_hash_type(i_value)
                            all_records.append((ip, i_value, htype))

                    for actor in threat_actors:
                        all_records.append((ip, actor.strip(), "THREAT_ACTOR"))
        except Exception as e:
            logging.error(f"[OTX SUBSCRIBED ERROR Page {page}] {e}")

    return all_records

def fetch_virustotal_related(ip):
    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=10)
        data = r.json().get("data", {}).get("attributes", {})
        return [(ip, res.get("host_name"), "DOMAIN") for res in data.get("resolutions", []) if res.get("host_name")]
    except Exception as e:
        logging.error(f"[VT ERROR] {ip}: {e}")
        return []

def fetch_threatminer_related(ip):
    try:
        r = requests.get(f"https://api.threatminer.org/v2/host.php?q={ip}&rt=5", timeout=10)
        return [(ip, domain, "DOMAIN") for domain in r.json().get("results", [])]
    except Exception as e:
        logging.error(f"[TM ERROR] {ip}: {e}")
        return []

# ========== DATABASE ==========
def insert_into_threat_ips(ip, country, city, isp, asn, ports):
    try:
        cursor.execute('''
            INSERT INTO threat_ips (ip_address, source, confidence_score, abuse_categories, country, city, isp, asn, shodan_ports)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (ip_address) DO UPDATE SET last_seen = CURRENT_TIMESTAMP;
        ''', (ip, 'AbuseIPDB', 100, 'Blacklisted', country, city, isp, asn, ports))
        conn.commit()
    except Exception as e:
        logging.error(f"[DB ERROR threat_ips] {ip}: {e}")
        conn.rollback()

def insert_into_related_indicators(records):
    try:
        for ip, indicator, indicator_type in records:
            cursor.execute('''
                INSERT INTO related_indicators (ip_address, indicator, indicator_type)
                VALUES (%s, %s, %s)
                ON CONFLICT DO NOTHING;
            ''', (ip, indicator, indicator_type))
        conn.commit()
    except Exception as e:
        logging.error(f"[DB ERROR indicators] {e}")
        conn.rollback()

# ========== MAIN ==========
def run_pipeline():
    abuse_ips = fetch_abuseipdb_ips()
    subscribed_records = fetch_subscribed_otx_indicators(pages=3)

    print(f"[INFO] AbuseIPDB: {len(abuse_ips)} | OTX Indicators: {len(subscribed_records)}")

    for ip in abuse_ips:
        if not is_valid_ip(ip): continue
        country, city, isp, asn = enrich_ipinfo(ip)
        ports = enrich_ports(ip)
        insert_into_threat_ips(ip, country, city, isp, asn, ports)

        related = fetch_virustotal_related(ip) or fetch_threatminer_related(ip)
        insert_into_related_indicators(related)

    if subscribed_records:
        insert_into_related_indicators(subscribed_records)

    print("[✓] All processing complete.")

# ========== LOOP ==========
if __name__ == "__main__":
    while True:
        print(f"\n[~] Run started at {datetime.now()}")
        run_pipeline()
        time.sleep(3600)
