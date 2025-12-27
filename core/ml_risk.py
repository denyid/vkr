# core/ml_risk.py — оценка риска устройства по простым эвристикам

def heuristic_score(features: dict) -> int:
    """
    Простая эвристическая модель оценки риска.
    features:
      open_ports_count  — количество открытых портов
      snmp_public       — открыт SNMP с public
      telnet_open       — открыт Telnet
      has_cve_high      — есть высокие CVE
      default_creds     — используются дефолтные учётные данные
    Возвращает 0–100 баллов риска.
    """
    score = 0
    # базовые факторы
    score += min(features.get("open_ports_count", 0) * 3, 30)
    if features.get("snmp_public"): score += 25
    if features.get("telnet_open"): score += 25
    if features.get("has_cve_high"): score += 30
    if features.get("default_creds"): score += 15
    # нормализация
    return int(min(score, 100))
