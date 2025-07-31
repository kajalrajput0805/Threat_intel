import psycopg2
import requests
import logging
from datetime import datetime

# ========== CONFIG ==========
OTX_API_KEY = '0a4cf08c033112415b31dcc9d411c099b91b1bd10714d0f742c27f19a013be98'
DB_CONFIG = {
    'host': 'localhost',
    'dbname': 'Threat_data',
    'user': 'postgres',
    'password': 'kajal@123',
    'port': 5432
}

# ========== LOGGING ==========
logging.basicConfig(
    filename='otx_enrichment.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ========== GET EXISTING IPS ==========
def get_existing_ips(cursor):
    cursor.execute("SELECT ip_address FROM threat_ips;")
    return set(row[0] for row in cursor.fetchall())

# ========== GET IP PULSES FROM OTX ==========
def fetch_pulses_from_otx():
    headers = {'X-OTX-API-KEY': OTX_API_KEY}
    url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
    collected = []
    page = 1

    while True:
        paged_url = f"{url}?page={page}"
        r = requests.get(paged_url, headers=headers, timeout=10)
        if r.status_code != 200:
            break
        data = r.json()
        results = data.get("results", [])
        if not results:
            break

        for pulse in results:
            indicators = pulse.get("indicators", [])
            author = pulse.get("author_name", "")
            for i in indicators:
                if i.get("type") == "IPv4":
                    collected.append({
                        'ip': i.get("indicator"),
                        'actor': author,
                        'pulse_name': pulse.get("name", ""),
                        'indicators': indicators  # include all indicators
                    })

        if not data.get("next", None):
            break
        page += 1

    return collected

# ========== DB INSERTION ==========
def insert_threat_ip(cursor, ip):
    try:
        cursor.execute("""
            INSERT INTO threat_ips (ip_address, source, confidence_score, abuse_categories)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING;
        """, (ip, 'OTX', 90, 'OTX Pulse'))
    except Exception as e:
        logging.error(f"[DB INSERT threat_ips] {ip}: {e}")

def insert_indicators(cursor, ip, actor, indicators):
    for item in indicators:
        val = item.get("indicator")
        if not val or val == ip:
            continue

        itype = item.get("type", "").upper()
        if "URL" in itype:
            typ = "URL"
        elif "DOMAIN" in itype:
            typ = "DOMAIN"
        elif "HASH" in itype or itype in ["MD5", "SHA1", "SHA256"]:
            typ = "HASH"
        elif "ACTOR" in itype:
            typ = "ACTOR"
        else:
            continue

        try:
            cursor.execute("""
                INSERT INTO related_indicators (ip_address, indicator, indicator_type, threat_actor)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT DO NOTHING;
            """, (ip, val, typ, actor))
        except Exception as e:
            logging.error(f"[DB INSERT indicator] {ip} - {val}: {e}")

# ========== MAIN ==========
def main():
    with psycopg2.connect(**DB_CONFIG) as conn:
        with conn.cursor() as cursor:
            existing_ips = get_existing_ips(cursor)
            print(f"[INFO] Loaded {len(existing_ips)} known IPs from DB")

            pulse_data = fetch_pulses_from_otx()
            print(f"[INFO] Pulled {len(pulse_data)} IP entries from OTX pulses")

            for entry in pulse_data:
                ip = entry['ip']
                actor = entry['actor']
                indicators = entry['indicators']

                if ip not in existing_ips:
                    insert_threat_ip(cursor, ip)
                    print(f"[+] New IP added: {ip}")
                    logging.info(f"Inserted new IP: {ip}")
                else:
                    print(f"[~] Existing IP: {ip}")

                insert_indicators(cursor, ip, actor, indicators)

            conn.commit()
            print("[✓] Enrichment complete.")

if __name__ == "__main__":
    main()
