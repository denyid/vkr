import json, os, re

DB_FILE = os.path.join("system", "local_cve_db.json")

def load_db():
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def match_sysdescr(sysdescr):
    if not sysdescr:
        return []
    db = load_db()
    matches = []
    for e in db:
        patt = e.get("match_regex")
        try:
            if patt and re.search(patt, sysdescr, re.IGNORECASE):
                matches.append(e)
        except re.error:
            continue
    return matches
