import os
import json
import time

from core.portscanner import scan_host, scan_ip
from core.snmp_client import get_sysdescr
from core import tls_checker, cve_matcher, mitre_checks, ml_risk
from system import db

DEFAULT_PORTS = [22, 23, 80, 443, 161]

# Политика "живости" и отображения UDP
ALIVE_FROM_UDP = False        # учитывать UDP только если state == "open" (не open|filtered). По умолчанию — НЕ учитывать.
HIDE_UDP_WHEN_DEAD = True     # скрывать UDP-результаты для alive == False (чтобы не засорять отчёт)


def build_issues_and_advice(ip, open_ports, snmp_info, cves, risk):
    """
    На основе признаков формирует:
    - список конкретных "issues" с рекомендациями;
    - человекочитаемый текст совета.
    """
    issues = []

    # 1. Открытый Telnet
    if 23 in open_ports:
        issues.append({
            "id": "TELNET_OPEN",
            "title": "Открыт Telnet (23/tcp)",
            "severity": "HIGH",
            "description": "На устройстве доступен Telnet. Протокол передаёт пароли в открытом виде и считается небезопасным.",
            "recommendation": "Отключить Telnet и использовать SSH (22/tcp). Если отключить нельзя — ограничить доступ ACL и/или через VPN."
        })

    # 2. SNMP с public
    if snmp_info and "public" in str(snmp_info).lower():
        issues.append({
            "id": "SNMP_PUBLIC",
            "title": "SNMP community 'public'",
            "severity": "HIGH",
            "description": "Обнаружен SNMP с community строкой 'public'. Это дефолтное значение, его легко подобрать.",
            "recommendation": "Сменить community на уникальное, ограничить доступ к SNMP по IP или вообще отключить SNMP, если не используется."
        })

    # 3. HTTP без HTTPS
    if 80 in open_ports and 443 not in open_ports:
        issues.append({
            "id": "HTTP_NO_HTTPS",
            "title": "Веб-интерфейс только по HTTP",
            "severity": "MEDIUM",
            "description": "Доступен веб-интерфейс по HTTP без HTTPS — логины/пароли передаются незашифрованными.",
            "recommendation": "Включить HTTPS на устройстве, отключить HTTP или ограничить доступ к веб-интерфейсу административной сети."
        })

    # 4. HIGH CVE
    for c in cves or []:
        if c.get("severity", "").upper() == "HIGH":
            issues.append({
                "id": f"CVE_{c.get('cve')}",
                "title": f"HIGH CVE: {c.get('cve')}",
                "severity": "HIGH",
                "description": c.get("desc", "Критическая уязвимость прошивки устройства."),
                "recommendation": "Проверить наличие обновления прошивки у вендора и обновить устройство. "
                                  "При невозможности обновления — ограничить доступ к уязвимым сервисам (ACL/segmentation)."
            })

    # 5. Слишком много открытых портов
    if len(open_ports) > 20:
        issues.append({
            "id": "MANY_PORTS",
            "title": "Большое количество открытых портов",
            "severity": "MEDIUM",
            "description": f"На устройстве открыто {len(open_ports)} портов. Чем больше сервисов, тем шире поверхность атаки.",
            "recommendation": "Отключить неиспользуемые сервисы, фильтровать трафик на границе (межсетевые экраны, ACL)."
        })

    # Текстовый вывод по общему риску
    if risk >= 80:
        advice_text = (
            f"Общая оценка риска для {ip}: {risk}/100 (КРИТИЧЕСКИЙ уровень). "
            f"В первую очередь устраните сервисы с открытым доступом управления (Telnet, SNMP public, веб), "
            f"а также HIGH CVE через обновление прошивки и ограничение доступа."
        )
    elif risk >= 50:
        advice_text = (
            f"Общая оценка риска для {ip}: {risk}/100 (повышенный уровень). "
            f"Рекомендуется закрыть неиспользуемые порты, включить HTTPS вместо HTTP, "
            f"проверить настройки SNMP и по возможности обновить прошивку."
        )
    else:
        advice_text = (
            f"Общая оценка риска для {ip}: {risk}/100 (умеренный уровень). "
            f"Тем не менее стоит убедиться, что управленческие интерфейсы доступны только из админской сети, "
            f"а прошивка обновлена."
        )

    return issues, advice_text


def scan_device(ip, mode="quick", modules=None, custom_ports=None):
    """
    Сканирует ОДИН IP.

    mode: "quick" | "special" | "full"
    custom_ports: строка или список для режима quick, например "22,80,1000-1010"
    modules: list[str] из: "snmp", "cve", "mitre", "tls"
    """
    modules = modules or []

    # 1) Скан портов (TCP + UDP) — UDP в quick мы гасим, чтобы не спамил
    scan_result = scan_ip(ip, mode=mode, custom_ports=custom_ports)
    if mode == "quick":
        scan_result["udp_ports"] = {}
        scan_result["udp_special_ports"] = {}
        scan_result["udp_scanned_ports_count"] = 0

    open_ports         = scan_result.get("ports", {})               # TCP
    special_ports      = scan_result.get("special_ports", {})
    udp_ports          = scan_result.get("udp_ports", {})           # UDP
    udp_special_ports  = scan_result.get("udp_special_ports", {})
    scanned_tcp_count  = scan_result.get("scanned_ports_count", 0)
    scanned_udp_count  = scan_result.get("udp_scanned_ports_count", 0)

    # 2) Работа с БД
    dev_id = db.upsert_device(ip)
    now = int(time.time())

    # 3) SNMP (через UDP/161; если выключен/фильтруется — вернёт None)
    snmp_info = None
    if "snmp" in modules:
        try:
            snmp_info = get_sysdescr(ip)
        except Exception:
            snmp_info = None

    # 4) CVE по sysDescr
    cves = []
    if "cve" in modules and snmp_info:
        cves = cve_matcher.match_sysdescr(snmp_info)
        for c in cves:
            db.insert_vuln(
                dev_id,
                c.get("cve"),
                c.get("desc", ""),
                c.get("severity", "MEDIUM"),
            )

    # 5) MITRE
    mitre_findings = []
    if "mitre" in modules:
        record = {
            "ip": ip,
            "ports": open_ports,
            "udp_ports": udp_ports,
            "snmp": snmp_info,
            "cve_matches": cves,
        }
        mitre_findings = mitre_checks.run_mitre_checks(record)
        for f in mitre_findings:
            db.insert_mitre(
                dev_id,
                f["technique_id"],
                f["technique_name"],
                f.get("rule", ""),
                f.get("confidence", ""),
                f,
            )

    # 6) TLS-сертификат на 443/tcp
    tls_info = None
    if "tls" in modules and 443 in open_ports:
        tls_info = tls_checker.get_cert_info(ip, 443)

    # 7) Сохраняем TCP-сканы в БД
    for p, info in open_ports.items():
        db.insert_scan(
            dev_id,
            now,
            p,
            "tcp",
            info.get("state"),
            banner=info.get("banner"),
            snmp_sysdescr=(snmp_info if p == 161 else None),  # фактически TCP/161 не встретится, но оставим совместимость
            raw_json=json.dumps(info, ensure_ascii=False),
        )

    # 8) Сохраняем UDP-сканы в БД
    for p, info in udp_ports.items():
        db.insert_scan(
            dev_id,
            now,
            p,
            "udp",
            info.get("state"),
            banner=info.get("banner"),
            snmp_sysdescr=None,
            raw_json=json.dumps(info, ensure_ascii=False),
        )

    # 9) Оценка риска (UDP учитываем только если реально был ответ)
    udp_open_count = sum(1 for v in udp_ports.values() if (v or {}).get("state") == "open")
    features = {
        "open_ports_count": len(open_ports) + udp_open_count,          # НЕ раздуваем за счёт open|filtered
        "snmp_public": bool(snmp_info and "public" in str(snmp_info).lower()),
        "telnet_open": 23 in open_ports,                               # UDP:23 не имеет смысла
        "has_cve_high": any((c.get("severity", "").upper() == "HIGH") for c in cves),
        "default_creds": False,
    }
    risk = ml_risk.heuristic_score(features)
    db.insert_metric(dev_id, "risk", risk)

    # 10) Проблемы и рекомендации
    issues, advice_text = build_issues_and_advice(ip, open_ports, snmp_info, cves, risk)

    # 11) Корректная "живость" хоста
    alive_tcp      = bool(open_ports)
    alive_snmp     = bool(snmp_info)
    alive_udp_open = any(((v or {}).get("state") == "open") for v in udp_ports.values())
    alive_flag     = alive_tcp or alive_snmp or (ALIVE_FROM_UDP and alive_udp_open)

    # (опционально) чистим UDP-«шум» у мёртвых хостов
    if HIDE_UDP_WHEN_DEAD and not alive_flag:
        udp_ports.clear()
        udp_special_ports.clear()
        scanned_udp_count = 0

    return {
        "ip": ip,
        "alive": alive_flag,
        "ports": open_ports,
        "special_ports": special_ports,
        "udp_ports": udp_ports,
        "udp_special_ports": udp_special_ports,
        "snmp": snmp_info if "snmp" in modules else None,
        "cves": cves if "cve" in modules else [],
        "mitre": mitre_findings if "mitre" in modules else [],
        "tls": tls_info if "tls" in modules else None,
        "risk": risk,
        "issues": issues,
        "advice": advice_text,
        "scanned_ports_count": scanned_tcp_count,
        "udp_scanned_ports_count": scanned_udp_count,
        "scan_mode": mode,
    }



def scan_network(ips, mode="quick", modules=None, custom_ports=None):
    """
    Сканирует список IP, сохраняет JSON-отчёт и возвращает список результатов.
    """
    modules = modules or []
    results = []
    for ip in ips:
        try:
            res = scan_device(ip, mode=mode, modules=modules, custom_ports=custom_ports)
        except Exception as e:
            res = {"ip": ip, "error": str(e)}
        results.append(res)

    out_dir = os.path.join("data", "reports")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"scan_{int(time.time())}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    return results