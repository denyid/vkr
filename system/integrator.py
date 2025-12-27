# system/integrator.py — отправка результатов во внешние системы (опционально)
import os
import requests

# URL Elastic (если нужно)
ELASTIC_URL = os.environ.get("ELASTIC_URL")

# Настройки Telegram
# ОБЯЗАТЕЛЬНО: в переменные окружения нужно положить TG_TOKEN и TG_CHAT_ID
TG_TOKEN = "8081738254:AAHGDB-EUxUS09_rrQ35b2UYRQcl1DGE8bg"        # токен бота
TG_CHAT = "-1003336989283"       # ID чата или канала

# Настройки Slack (если нужно)
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK")


def send_to_elastic(doc):
    """Отправка JSON-документа в ElasticSearch (опционально)."""
    if not ELASTIC_URL:
        return False, "Elastic URL not set"
    try:
        r = requests.post(ELASTIC_URL, json=doc, timeout=5)
        return r.ok, r.text
    except Exception as e:
        return False, str(e)


def send_telegram(msg: str):
    """
    Отправка текстового сообщения в Telegram-бота.

    Требует:
      - переменная окружения TG_TOKEN  = токен бота
      - переменная окружения TG_CHAT_ID = ID чата/канала
    """
    if not TG_TOKEN or not TG_CHAT:
        return False, "Telegram not configured"

    # Лимита Telegram (4096 символов), чтобы бот не обрубался
    if len(msg) > 4000:
        msg = msg[:4000] + " ..."

    try:
        url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        payload = {
            "chat_id": TG_CHAT,
            "text": msg,
            "disable_web_page_preview": True,
        }
        r = requests.post(url, json=payload, timeout=5)
        return r.ok, r.text
    except Exception as e:
        return False, str(e)


def send_slack(msg: str):
    """Отправка сообщения в Slack (опционально)."""
    if not SLACK_WEBHOOK:
        return False, "Slack not configured"
    try:
        r = requests.post(SLACK_WEBHOOK, json={"text": msg}, timeout=5)
        return r.ok, r.text
    except Exception as e:
        return False, str(e)
