import asyncio
import logging

from puresnmp import Client, V2C, PyWrapper

logger = logging.getLogger(__name__)


async def _async_get_sysdescr(ip: str, community: str = "public") -> str | None:
    """
    Внутренняя async-функция для получения sysDescr через puresnmp.

    Использует SNMPv2c (V2C) и OID 1.3.6.1.2.1.1.1.0 (sysDescr.0).
    """
    try:
        # Создаём клиента и оборачиваем его в PyWrapper, чтобы на выходе были
        # нормальные питоновские типы, а не SNMP-специфичные объекты.
        client = PyWrapper(Client(ip, V2C(community)))

        # Пример из официальной документации puresnmp:
        # output = await client.get("1.3.6.1.2.1.1.1.0")
        # 
        value = await client.get("1.3.6.1.2.1.1.1.0")

        # На многих устройствах это байты → декодируем аккуратно
        if isinstance(value, (bytes, bytearray)):
            try:
                return value.decode("utf-8", errors="ignore")
            except Exception:
                return str(value)

        return str(value)

    except Exception as e:
        logger.warning(f"SNMP (puresnmp) query failed for {ip}: {e}")
        return None


def get_sysdescr(ip: str, community: str = "public", timeout: int = 2, retries: int = 1) -> str | None:
    """
    Возвращает SNMP sysDescr (описание устройства) или None.

    Совместимая с прежней версия сигнатура:
      - ip        — IP-адрес устройства
      - community — SNMP community (по умолчанию 'public')
      - timeout   — сейчас НЕ используется (puresnmp использует свои дефолты)
      - retries   — сейчас НЕ используется

    Внутри синхронной функции просто запускаем async-функцию через asyncio.
    """
    try:
        # Обычный случай: Flask/потоки → event loop ещё не запущен
        return asyncio.run(_async_get_sysdescr(ip, community))
    except RuntimeError as e:
        # На всякий случай fallback, если вдруг вызов идёт из уже работающего event loop
        logger.debug(f"get_sysdescr: fallback event loop for {ip}: {e}")
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(_async_get_sysdescr(ip, community))
        finally:
            loop.close()
            asyncio.set_event_loop(None)
