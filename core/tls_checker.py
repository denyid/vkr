# core/tls_checker.py — более совместимая проверка TLS-сертификата
import ssl
import socket
import tempfile
import os


def _extract_name_from_seq(seq):
    """
    subject/issuer из ssl.getpeercert() имеют вид:
      [
        (('commonName', 'one.one.one.one'),),
        (('countryName', 'US'),),
        ...
      ]
    Превратим это в простой dict.
    """
    result = {}
    for rdn in seq or []:
        for key, value in rdn:
            result[key] = value
    return result


def _x509_name_to_dict(x509_name):
    """
    Преобразует cryptography.x509.Name в dict:
      CN -> commonName, C -> countryName и т.д.
    """
    result = {}
    for attr in x509_name:
        # Пытаемся использовать человекочитаемое имя, если оно есть
        name = getattr(attr.oid, "_name", None) or attr.oid.dotted_string
        result[name] = attr.value
    return result


def _decode_cert_pem(pem_str: str):
    """
    Разбираем PEM-сертификат через библиотеку cryptography.
    Это кроссплатформенный способ, не завязанный на приватный ssl._test_decode_cert.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError as e:
        # Если cryptography не установлена — бросаем понятную ошибку
        raise RuntimeError("cryptography is not installed (pip install cryptography)") from e

    cert = x509.load_pem_x509_certificate(pem_str.encode("ascii"), default_backend())

    subject = _x509_name_to_dict(cert.subject)
    issuer = _x509_name_to_dict(cert.issuer)

    # Даты делаем в ISO-формате, его удобно парсить/отображать
    not_before = cert.not_valid_before.isoformat()
    not_after = cert.not_valid_after.isoformat()

    return {
        "subject": subject,
        "issuer": issuer,
        "notBefore": not_before,
        "notAfter": not_after,
    }


def _try_modern_context(ip, port, timeout, hostname):
    """
    Первая попытка: нормальный modern TLS-контекст.
    Может вернуть:
      - dict с полями subject/issuer/даты
      - None, если cert пустой
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            # Некоторые сервера при CERT_NONE/без верификации отдают пустой dict
            if not cert:
                return None

            # subject/issuer в виде "корявых" структур -> делаем dict
            subject = _extract_name_from_seq(cert.get("subject"))
            issuer = _extract_name_from_seq(cert.get("issuer"))

            return {
                "subject": subject,
                "issuer": issuer,
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
            }


def get_cert_info(ip, port=443, timeout=3, hostname=None):
    """
    Возвращает информацию о TLS-сертификате или ошибку:

      {
        "subject": {...} / None,
        "issuer": {...} / None,
        "notBefore": "...",
        "notAfter":  "...",
      }

      или

      {
        "error": "TLS check failed: ...",
        "subject": None,
        "issuer": None,
        "notBefore": None,
        "notAfter": None
      }

    Логика:
      1) Пытаемся через обычный TLS-контекст (getpeercert)
      2) Если cert пустой или ошибка — пытаемся получить PEM через ssl.get_server_certificate
         и разбираем его вручную через cryptography.
    """
    host = hostname or ip

    # 1. Пытаемся через обычный TLS-контекст
    try:
        info = _try_modern_context(ip, port, timeout, host)
        if info is not None:
            return info
    except Exception:
        # просто переходим к fallback
        pass

    # 2. Фоллбэк: ssl.get_server_certificate → PEM → cryptography
    try:
        pem = ssl.get_server_certificate((ip, port))
        if not pem:
            return {
                "error": "TLS check failed: empty PEM from server",
                "subject": None,
                "issuer": None,
                "notBefore": None,
                "notAfter": None,
            }

        info = _decode_cert_pem(pem)
        if not info:
            return {
                "error": "TLS check failed: cannot decode PEM cert",
                "subject": None,
                "issuer": None,
                "notBefore": None,
                "notAfter": None,
            }

        return info

    except Exception as e:
        return {
            "error": f"TLS check failed: {e}",
            "subject": None,
            "issuer": None,
            "notBefore": None,
            "notAfter": None,
        }
