import json, os, re
MAP_FILE = os.path.join("data", "mitre_mappings.json")

def load_mappings():
    if not os.path.exists(MAP_FILE):
        return []
    with open(MAP_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

MAPPINGS = load_mappings()

def _rule_ssh_open(rec): return 22 in rec.get("ports", {})
def _rule_http_open(rec): return 80 in rec.get("ports", {}) or 443 in rec.get("ports", {})
def _rule_snmp_sysdescr(rec): return bool(rec.get("snmp"))
def _rule_telnet_open(rec): return 23 in rec.get("ports", {})
def _rule_http_fw(rec):
    for v in rec.get("ports", {}).values():
        b = v.get("banner", "")
        if re.search(r"eltex|firmware|version", b, re.I):
            return True
    return False
def _rule_known_cve(rec): return bool(rec.get("cve_matches"))

RULES = {
    "snmp_sysdescr": _rule_snmp_sysdescr,
    "telnet_open": _rule_telnet_open,
    "http_fw": _rule_http_fw,
    "known_cve": _rule_known_cve,
    "ssh_open": _rule_ssh_open,
    "http_open": _rule_http_open
}


def run_mitre_checks(record):
    findings = []
    for m in MAPPINGS:
        for rule in m.get("detection_rules", []):
            fn = RULES.get(rule)
            if fn and fn(record):
                findings.append({
                    "technique_id": m.get("id"),
                    "technique_name": m.get("name"),
                    "rule": rule,
                    "confidence": "medium"
                })
    return findings

