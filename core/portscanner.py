# core/portscanner.py — портсканер с поддержкой TCP (quick/special/full) и базового UDP-сканирования
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Предустановленные "специальные" TCP-порты
SPECIAL_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 3306, 3389, 8080, 8443]

# Набор интересных UDP-портов, которые сканируем по умолчанию
UDP_SPECIAL_PORTS = [53, 67, 69, 123, 161, 500, 1900, 1194]



def parse_ports_from_string(s):
    """
    Парсит строку вида "22,80,1000-1010" → список уникальных портов (ints).
    Возвращает пустой список при ошибке/пустой строке.
    """
    if not s:
        return []
    out = set()
    parts = s.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start = int(start.strip())
                end = int(end.strip())
                if end < start:
                    start, end = end, start
                for p in range(start, end + 1):
                    if 1 <= p <= 65535:
                        out.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    out.add(p)
            except ValueError:
                continue
    return sorted(out)


def tcp_scan_port(ip, port, timeout=1.0):
    """Проверка одного TCP-порта. Возвращает dict с состоянием или None, если порт закрыт/недоступен."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        res = sock.connect_ex((ip, port))
        if res != 0:
            return None  # порт не открыт
        banner = ""
        try:
            # пробуем отправить пустую "пробу", чтобы некоторые сервисы выдали баннер/ошибку
            sock.sendall(b"\r\n\r\n")
        except Exception:
            pass
        try:
            data = sock.recv(1024)
            if data:
                banner = data.decode(errors="ignore")
        except Exception:
            pass
        return {"state": "open", "banner": banner}
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def udp_scan_port(ip, port, timeout=1.0):
    """
    Простейшая проверка UDP-порта.
    Возвращает:
      {"state": "open", "banner": "..."}       — если получили ответ
      {"state": "open|filtered", "banner": ""} — если не получили ответа (UDP сложно различить)
    или None при явной ошибке.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # Отправляем пустой пакет; для ряда сервисов (SNMP, DNS, NTP) можно в будущем делать осмысленный payload
        sock.sendto(b"\x00", (ip, port))
        try:
            data, _ = sock.recvfrom(1024)
            banner = ""
            if data:
                banner = data.decode(errors="ignore")
            return {"state": "open", "banner": banner}
        except socket.timeout:
            # Не получили ответа — порт может быть открыт или фильтроваться
            return {"state": "open|filtered", "banner": ""}
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def scan_host(ip, ports, threads=100, timeout=1.0):
    """
    Параллельное TCP-сканирование хоста по списку портов.
    Возвращает словарь: {port: {"state": "...", "banner": "..."}, ...}
    """
    found = {}

    def worker(p):
        return p, tcp_scan_port(ip, p, timeout=timeout)

    with ThreadPoolExecutor(max_workers=max(1, min(len(ports), threads))) as ex:
        futures = [ex.submit(worker, p) for p in ports]
        for fut in as_completed(futures):
            p, res = fut.result()
            if res:
                found[p] = res
    return found


def scan_udp_host(ip, ports, threads=50, timeout=1.0):
    """
    Параллельное UDP-сканирование хоста по списку портов.
    Возвращает словарь: {port: {"state": "...", "banner": "..."}, ...}
    """
    found = {}

    def worker(p):
        return p, udp_scan_port(ip, p, timeout=timeout)

    with ThreadPoolExecutor(max_workers=max(1, min(len(ports), threads))) as ex:
        futures = [ex.submit(worker, p) for p in ports]
        for fut in as_completed(futures):
            p, res = fut.result()
            if res:
                found[p] = res
    return found


def scan_ip(ip, mode="quick", custom_ports=None, timeout=1.0, threads=100):
    """
    Высокоуровневый вызов:
      TCP:
        - quick   → порты только из custom_ports
        - special → SPECIAL_PORTS
        - full    → 1..65535
      UDP:
        - quick   → порты только из custom_ports
        - special → UDP_SPECIAL_PORTS
        - full    → 1..65535

    Возвращает словарь:
      {
        "ip": ...,
        "alive": True/False,
        "ports": {...},              # TCP
        "special_ports": {...},      # TCP-избранные
        "udp_ports": {...},          # UDP
        "udp_special_ports": {...},  # UDP-избранные
        "scanned_ports_count": N,
        "udp_scanned_ports_count": M,
      }
    """
    # ---------- TCP-часть (как раньше) ----------
    if mode == "full":
        tcp_ports = list(range(1, 65536))
        timeout = max(timeout, 0.2)
        threads = min(threads, 300)

    elif mode == "special":
        tcp_ports = SPECIAL_PORTS[:]
        timeout = max(timeout, 0.6)

    else:  # quick
        if isinstance(custom_ports, str):
            tcp_ports = parse_ports_from_string(custom_ports)
        elif isinstance(custom_ports, (list, tuple)):
            tmp = []
            for p in custom_ports:
                try:
                    tmp.append(int(p))
                except Exception:
                    continue
            tcp_ports = tmp
        else:
            tcp_ports = []
        timeout = max(timeout, 0.6)

    tcp_ports = sorted({p for p in tcp_ports if 1 <= int(p) <= 65535})

    if not tcp_ports:
        # если ни одного TCP порта не задано — считаем хост "непросканированным"
        found_tcp = {}
        special_found_tcp = {}
        alive = False
        scanned_tcp_count = 0
    else:
        found_tcp = scan_host(ip, tcp_ports, threads=threads, timeout=timeout)
        special_found_tcp = {p: found_tcp[p] for p in found_tcp if p in SPECIAL_PORTS}
        alive = bool(found_tcp)
        scanned_tcp_count = len(tcp_ports)

        # ---------- UDP-часть ----------
    if mode == "full":
        # full-режим: UDP тоже полноскан — ОСТОРОЖНО, это очень шумно и долго
        udp_ports = list(range(1, 65536))

    elif mode == "special":
        # special: только заранее отобранные интересные UDP-порты
        udp_ports = UDP_SPECIAL_PORTS[:]

    else:  # quick
        # quick: по умолчанию вообще НЕ сканируем UDP,
        # чтобы не засорять отчёты. При желании можно будет
        # ввести отдельный параметр custom_udp_ports.
        udp_ports = []


    udp_ports = sorted({p for p in udp_ports if 1 <= int(p) <= 65535})

    if udp_ports:
        found_udp = scan_udp_host(ip, udp_ports, threads=min(len(udp_ports), 50), timeout=1.0)
        special_found_udp = {p: found_udp[p] for p in found_udp if p in UDP_SPECIAL_PORTS}
        scanned_udp_count = len(udp_ports)
    else:
        found_udp = {}
        special_found_udp = {}
        scanned_udp_count = 0

    return {
        "ip": ip,
        "alive": alive,
        "ports": found_tcp,
        "special_ports": special_found_tcp,
        "udp_ports": found_udp,
        "udp_special_ports": special_found_udp,
        "scanned_ports_count": scanned_tcp_count,
        "udp_scanned_ports_count": scanned_udp_count,
    }