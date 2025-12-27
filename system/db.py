# system/db.py — SQLite база данных для ELTEX-Audit
import sqlite3, threading, os, json, time
from contextlib import contextmanager

DB_PATH = os.environ.get("ELTEX_DB", "eltex_audit.db")
_lock = threading.Lock()

@contextmanager
def _get_conn():
    with _lock:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        try:
            yield conn
        finally:
            conn.close()

def init_db():
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS devices(
            id INTEGER PRIMARY KEY,
            ip TEXT UNIQUE,
            hostname TEXT,
            mac TEXT,
            model TEXT,
            fw_version TEXT,
            first_seen INTEGER,
            last_seen INTEGER
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY,
            device_id INTEGER,
            scan_time INTEGER,
            port INTEGER,
            service TEXT,
            state TEXT,
            banner TEXT,
            snmp_sysdescr TEXT,
            raw_json TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities(
            id INTEGER PRIMARY KEY,
            device_id INTEGER,
            cve TEXT,
            description TEXT,
            severity TEXT,
            source TEXT,
            first_seen INTEGER,
            last_seen INTEGER,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS mitre_findings(
            id INTEGER PRIMARY KEY,
            device_id INTEGER,
            technique_id TEXT,
            technique_name TEXT,
            rule TEXT,
            confidence TEXT,
            evidence TEXT,
            found_at INTEGER,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS metrics(
            id INTEGER PRIMARY KEY,
            device_id INTEGER,
            metric_time INTEGER,
            metric_name TEXT,
            metric_value REAL,
            labels TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS history(
            id INTEGER PRIMARY KEY,
            device_id INTEGER,
            event_time INTEGER,
            event_type TEXT,
            details TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )""")
        conn.commit()

def upsert_device(ip, hostname=None, mac=None, model=None, fw_version=None):
    now = int(time.time())
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM devices WHERE ip=?", (ip,))
        r = cur.fetchone()
        if r:
            cur.execute("UPDATE devices SET hostname=?,mac=?,model=?,fw_version=?,last_seen=? WHERE id=?",
                        (hostname,mac,model,fw_version,now,r[0]))
            device_id = r[0]
        else:
            cur.execute("INSERT INTO devices(ip,hostname,mac,model,fw_version,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)",
                        (ip,hostname,mac,model,fw_version,now,now))
            device_id = cur.lastrowid
        conn.commit()
        return device_id

def insert_scan(device_id, scan_time, port, service, state, banner=None, snmp_sysdescr=None, raw_json=None):
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO scans(device_id,scan_time,port,service,state,banner,snmp_sysdescr,raw_json) VALUES(?,?,?,?,?,?,?,?)",
                    (device_id,scan_time,port,service,state,banner,snmp_sysdescr,raw_json))
        conn.commit()

def insert_vuln(device_id, cve, desc, severity="MEDIUM", source="local"):
    now = int(time.time())
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM vulnerabilities WHERE device_id=? AND cve=?", (device_id,cve))
        r = cur.fetchone()
        if r:
            cur.execute("UPDATE vulnerabilities SET description=?,severity=?,source=?,last_seen=? WHERE id=?",
                        (desc,severity,source,now,r[0]))
        else:
            cur.execute("INSERT INTO vulnerabilities(device_id,cve,description,severity,source,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)",
                        (device_id,cve,desc,severity,source,now,now))
        conn.commit()

def insert_mitre(device_id, tid, name, rule, conf, evidence):
    with _get_conn() as conn:
        cur = conn.cursor()
        now = int(time.time())
        cur.execute("INSERT INTO mitre_findings(device_id,technique_id,technique_name,rule,confidence,evidence,found_at) VALUES(?,?,?,?,?,?,?)",
                    (device_id,tid,name,rule,conf,json.dumps(evidence,ensure_ascii=False),now))
        conn.commit()

def insert_metric(device_id, name, value, labels=None):
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO metrics(device_id,metric_time,metric_name,metric_value,labels) VALUES(?,?,?,?,?)",
                    (device_id,int(time.time()),name,value,json.dumps(labels) if labels else None))
        conn.commit()

def insert_history(device_id, etype, details):
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO history(device_id,event_time,event_type,details) VALUES(?,?,?,?)",
                    (device_id,int(time.time()),etype,json.dumps(details,ensure_ascii=False)))
        conn.commit()
