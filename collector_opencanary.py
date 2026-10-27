#!/usr/bin/env python3
"""
collector_opencanary.py
Tail de alerts.json Wazuh, extraction des evenements OpenCanary et
echecs d'authentification, transmission au moteur SOAR.
"""

import json
import os
import threading
import time

from soar_engine import SOAREngine

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
HONEYPOT_AGENT_ID = {"002", "004"}

# ID de votre regle custom OpenCanary (local_rules.xml)
OPENCANARY_RULE_ID = "100100"

# IDs de regles Wazuh pour echecs d'authentification SSH (a verifier/adapter)
AUTH_FAILURE_RULE_IDS = {"5710", "5716", "5720", "5760", "5551", "60122", "60204"}


def tail_f(path):
    def open_file():

        f = open(ALERTS_FILE, 'r', encoding='utf-8', errors='replace')
        f.seek(0, 2)
        return f, os.fstat(f.fileno()).st_ino

    f, last_inode = open_file()
    while True:
        line = f.readline()
        if not line:
            try:
                current_inode = os.stat(path).st_ino
            except FileNotFoundError:
                current_inode = None
            if current_inode != last_inode:
                f.close()
                f, last_inode = open_file()
                continue
            time.sleep(1)
            continue
        yield line


def main():
    engine = SOAREngine()
    threading.Thread(target=engine.expiration_loop, daemon=True).start()

    print("Collecteur OpenCanary/Wazuh demarre, ecoute de alerts.json...")

    for line in tail_f(ALERTS_FILE):
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        agent_id = alert.get("agent", {}).get("id")
        rule_id = alert.get("rule", {}).get("id")
        data = alert.get("data", {})

        if agent_id not in HONEYPOT_AGENT_ID:
            continue

        if rule_id == OPENCANARY_RULE_ID:
            src_ip = data.get("src_host")
            if src_ip:
                engine.add_opencanary_event(src_ip)

        elif rule_id in AUTH_FAILURE_RULE_IDS:
            src_ip = data.get("srcip") or data.get("src_host") or data.get("win", {}).get("eventdata", {}).get("ipAddress")

            if src_ip:

                engine.add_wazuh_auth_failure(src_ip)
if __name__ == "__main__":
    main()
