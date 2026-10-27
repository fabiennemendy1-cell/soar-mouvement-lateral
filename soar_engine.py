#!/usr/bin/env python3
"""
soar_engine.py
Moteur de scoring et de blocage automatique
Corrélation OpenCanary + Wazuh - détection de mouvement latéral
"""

import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta

# ------------------------------------------------------------------
# CONFIGURATION - à adapter à votre environnement
# ------------------------------------------------------------------
OPENCANARY_WINDOW = timedelta(minutes=5)
OPENCANARY_POINTS = 10

WAZUH_AUTH_WINDOW = timedelta(hours=72)
WAZUH_AUTH_POINTS = 2

BLOCK_THRESHOLD = 20
BLOCK_DURATION = timedelta(minutes=15)

# Accès pfSense (à adapter : IP de gestion réelle de pfSense)
PFSENSE_HOST = "10.0.4.1"
PFSENSE_USER = "admin"
PFSENSE_SSH_KEY = "/home/soc/.ssh/soar_pfsense"
PFSENSE_TABLE = "soar_blocklist"

LOG_FILE = "/home/soc/soar/soar_engine.log"


def log(msg):
    line = f"[{datetime.now().isoformat()}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


class SOAREngine:
    def __init__(self):
        self.events = defaultdict(list)
        self.blocked = {}
        self.lock = threading.Lock()

    def add_opencanary_event(self, src_ip):
        self._add_event(src_ip, OPENCANARY_POINTS, "opencanary")

    def add_wazuh_auth_failure(self, src_ip):
        self._add_event(src_ip, WAZUH_AUTH_POINTS, "wazuh_auth")

    def _add_event(self, src_ip, points, source):
        with self.lock:
            now = datetime.now()
            self.events[src_ip].append((now, points, source))
            log(f"Evenement recu : {source} src={src_ip} +{points}pts")
            self._evaluate(src_ip)

    def _score(self, src_ip):
        now = datetime.now()
        total = 0
        for ts, points, source in self.events[src_ip]:
            if source == "opencanary" and now - ts <= OPENCANARY_WINDOW:
                total += points
            elif source == "wazuh_auth" and now - ts <= WAZUH_AUTH_WINDOW:
                total += points
        return total

    def _evaluate(self, src_ip):
        score = self._score(src_ip)
        log(f"Score courant pour {src_ip} : {score}/{BLOCK_THRESHOLD}")
        if score >= BLOCK_THRESHOLD and src_ip not in self.blocked:
            self.block_ip(src_ip)

    def block_ip(self, src_ip):
        cmd = [
            "ssh", "-i", PFSENSE_SSH_KEY,
            "-o", "StrictHostKeyChecking=no",
            f"{PFSENSE_USER}@{PFSENSE_HOST}",
            f"pfctl -t {PFSENSE_TABLE} -T add {src_ip}"
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            expiry = datetime.now() + BLOCK_DURATION
            self.blocked[src_ip] = expiry
            log(f"BLOCAGE applique : {src_ip} (expire a {expiry.isoformat()})")
        except subprocess.CalledProcessError as e:
            log(f"Echec du blocage {src_ip} : {e.stderr.decode(errors='ignore')}")
        except Exception as e:
            log(f"Erreur SSH lors du blocage {src_ip} : {e}")

    def unblock_ip(self, src_ip):
        cmd = [
            "ssh", "-i", PFSENSE_SSH_KEY,
            "-o", "StrictHostKeyChecking=no",
            f"{PFSENSE_USER}@{PFSENSE_HOST}",
            f"pfctl -t {PFSENSE_TABLE} -T delete {src_ip}"
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            log(f"DEBLOCAGE (expiration) : {src_ip}")
        except Exception as e:
            log(f"Erreur lors du deblocage {src_ip} : {e}")
        finally:
            self.blocked.pop(src_ip, None)

    def expiration_loop(self):
        while True:
            now = datetime.now()
            with self.lock:
                expired = [ip for ip, exp in self.blocked.items() if now >= exp]
            for ip in expired:
                self.unblock_ip(ip)
            time.sleep(30)
