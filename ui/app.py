from flask import (
    Flask,
    render_template_string,
    request,
    jsonify,
    Response,
    send_from_directory,
    abort,
)
import threading
import time
import os
import glob
import json
import ipaddress
import queue

from system import integrator
from system import db
from core import python_scanner
from core.monitor import get_system_metrics
from apscheduler.schedulers.background import BackgroundScheduler  # APScheduler

app = Flask(__name__)

DB_PATH = db.DB_PATH

# --- путь к каталогу отчётов относительно корня проекта, а не ui/ ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))      # .../Project3/ui
PROJECT_ROOT = os.path.dirname(BASE_DIR)                   # .../Project3
REPORT_DIR = os.path.join(PROJECT_ROOT, "data", "reports") # .../Project3/data/reports
os.makedirs(REPORT_DIR, exist_ok=True)

SCAN_STATE = {
    "running": False,
    "target": None,
    "modules": [],
    "started_at": None,
    "last_message": "",
    "thread": None,
    "mode": None,
}
LOCK = threading.Lock()
log_queue = queue.Queue()
STOP_SCAN = False

SCHEDULER = None  # глобальная ссылка на планировщик
AUTO_JOB_ID = "auto_scan"
AUTO_SCHEDULE = {
    "enabled": False,
    "every": None,
    "unit": None,
    "target": None,
    "mode": None,
    "custom_ports": None,
    "modules": [],
}


def log_event(msg: str):
    """
    Логируем событие:
      - отправляем в очередь для веб-интерфейса (SSE)
      - по возможности дублируем в Telegram-бота
    """
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"

    # Веб-интерфейс (SSE)
    log_queue.put(line)

    # Telegram (если настроен через переменные окружения)
    try:
        integrator.send_telegram(line)
    except Exception:
        # ничего не логируем, чтобы не уйти в рекурсию логов
        pass


@app.route("/api/logs")
def stream_logs():
    """
    Server-Sent Events (SSE): браузер открывает EventSource('/api/logs')
    и постоянно получает события "data: ...".
    """
    def event_stream():
        while True:
            msg = log_queue.get()
            yield f"data: {msg}\n\n"

    return Response(event_stream(), mimetype="text/event-stream")


# ---------- HTML-ИНТЕРФЕЙС ----------

HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Веб-интерфейс</title>
  <style>
    body{font-family:Segoe UI,Arial;padding:16px;background:#f5f5f5;}
    button{padding:6px 10px;margin-right:6px;cursor:pointer;}
    .box{background:#fff;padding:12px;margin-bottom:12px;border-radius:6px;box-shadow:0 0 4px #ccc;}
    pre{background:#111;color:#0f0;font-family:Consolas,monospace;padding:8px;height:420px;overflow:auto;margin:0;}
    label{margin-right:8px;}
    input[type="text"], input[type="number"]{padding:4px;}
    h2{margin-top:0;}
    small{color:#666;}
  </style>
</head>
<body>
  <h2>Сканер уязвимости сетевого оборудования</h2>

  <div class="box">
    <h3>Запуск сканирования</h3>
    <div>
      <label>Цель:
        <input id="target" placeholder="192.168.1.2,192.168.1.3-10,192.168.1.0/24" style="width:320px">
      </label>
    </div>
    <div style="margin-top:8px;">
      <label>Режим:
        <select id="scan_mode">
          <option value="quick">quick</option>
          <option value="special">special</option>
          <option value="full">full (1..65535)</option>
        </select>
      </label>
      <label>Персонализированные порты:
        <input id="custom_ports" placeholder="22,80,443,1000-1010" style="width:200px">
      </label>
    </div>
    <div style="margin-top:8px%;">
      <label><input type="checkbox" name="modules" value="snmp" checked> SNMP</label>
      <label><input type="checkbox" name="modules" value="cve" checked> CVE</label>
      <label><input type="checkbox" name="modules" value="mitre" checked> MITRE</label>
      <label><input type="checkbox" name="modules" value="tls"> TLS</label>
    </div>
    <div style="margin-top:10px;">
      <button onclick="startScan()"> Пуск</button>
      <button onclick="stopScan()"> Стоп</button>
    </div>
    <small></small>
  </div>

  <div class="box">
    <h3>Запуск автоматического сканирования по расписанию</h3>
    <div>
      <label><input type="checkbox" id="auto_enabled"> Включить автосканирование</label>
    </div>
    <div style="margin-top:8px;">
      <label>Каждые:
        <input id="auto_every" type="number" min="1" value="1" style="width:60px">
      </label>
      <label>
        <select id="auto_unit">
          <option value="minutes">минут</option>
          <option value="hours" selected>часов</option>
          <option value="days">дней</option>
          <option value="weeks">недель</option>
        </select>
      </label>
    </div>
    <div style="margin-top:8px;">
      <small></small>
    </div>
    <div style="margin-top:10px;">
      <button onclick="saveSchedule()"> Сохранить расписание</button>
    </div>
    <div style="margin-top:8px;">
      <small>Текущее расписание: <span id="schedule_status">не настроено</span></small>
    </div>
  </div>

  <div class="box">
    <h3>Логи</h3>
    <pre id="logs"></pre>
  </div>

  <div class="box">
    <h3>Состояние системы</h3>
    <div>CPU: <span id="cpu">-</span> %</div>
    <div>RAM: <span id="ram">-</span> %</div>
    <div>Потоки: <span id="thr">-</span></div>
  </div>

  <div class="box">
    <h3>Все отчёты</h3>
    <div id="reports">—</div>
  </div>

  <script>
    function startScan(){
      const t = document.getElementById('target').value.trim();
      const mode = document.getElementById('scan_mode').value;
      const custom = document.getElementById('custom_ports').value.trim() || null;
      const mods = [];
      document.querySelectorAll('input[name="modules"]:checked').forEach(cb => mods.push(cb.value));

      if(!t){
        alert("Укажи цель");
        return;
      }

      document.getElementById('logs').innerText = "";
      fetch('/api/scan', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ target: t, modules: mods, mode: mode, custom_ports: custom })
      }).then(r=>r.json()).then(js=>{
        logLine("API", js.message || "запрос отправлен");
      });
    }

    function stopScan(){
      fetch('/api/stop',{method:'POST'}).then(r=>r.json()).then(js=>{
        logLine("API", js.message || "команда остановки отправлена");
      });
    }

    function saveSchedule(){
      const t = document.getElementById('target').value.trim();
      const mode = document.getElementById('scan_mode').value;
      const custom = document.getElementById('custom_ports').value.trim() || null;
      const mods = [];
      document.querySelectorAll('input[name="modules"]:checked').forEach(cb => mods.push(cb.value));

      const enabled = document.getElementById('auto_enabled').checked;
      const every = parseInt(document.getElementById('auto_every').value, 10) || 0;
      const unit = document.getElementById('auto_unit').value;

      if (enabled) {
        if (!t) {
          alert("Чтобы включить автосканирование, укажи цель.");
          return;
        }
        if (every <= 0) {
          alert("Период должен быть положительным числом.");
          return;
        }
      }

      fetch('/api/schedule', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
          enabled: enabled,
          every: every,
          unit: unit,
          target: t,
          mode: mode,
          custom_ports: custom,
          modules: mods
        })
      }).then(r=>r.json()).then(js=>{
        logLine("SCHED", js.message || "расписание обновлено");
        if (js.status_text) {
          document.getElementById('schedule_status').innerText = js.status_text;
        }
        if (typeof js.enabled === "boolean") {
          document.getElementById('auto_enabled').checked = js.enabled;
        }
        if (js.every) {
          document.getElementById('auto_every').value = js.every;
        }
        if (js.unit) {
          document.getElementById('auto_unit').value = js.unit;
        }
      });
    }

    function logLine(prefix, text){
      const p = document.getElementById('logs');
      p.innerText += "[" + prefix + "] " + text + "\\n";
      p.scrollTop = p.scrollHeight;
    }

    // Подписка на SSE-логи
    const evt = new EventSource('/api/logs');
    evt.onmessage = (e)=>{
      const p = document.getElementById('logs');
      p.innerText += e.data + "\\n";
      p.scrollTop = p.scrollHeight;
    };

    function updateSystem(){
      fetch('/api/system_load').then(r=>r.json()).then(js=>{
        document.getElementById('cpu').innerText = js.cpu_percent;
        document.getElementById('ram').innerText = js.mem_percent;
        document.getElementById('thr').innerText = js.threads;
      });
      fetch('/api/reports').then(r=>r.json()).then(js=>{
        let html = '<ul>';
        js.forEach(x => {
          html += '<li>'+ x.name +' - <a href="/reports/'+ x.name +'" target="_blank">открыть</a></li>';
        });
        html += '</ul>';
        document.getElementById('reports').innerHTML = html;
      });
      fetch('/api/schedule').then(r=>r.json()).then(js=>{
        if (js.status_text) {
          document.getElementById('schedule_status').innerText = js.status_text;
        }
        if (typeof js.enabled === "boolean") {
          document.getElementById('auto_enabled').checked = js.enabled;
        }
        if (js.every) {
          document.getElementById('auto_every').value = js.every;
        }
        if (js.unit) {
          document.getElementById('auto_unit').value = js.unit;
        }
      });
    }

    setInterval(updateSystem, 3000);
    window.onload = updateSystem;
  </script>
</body>
</html>
"""


def expand_target(target):
    """
    Поддерживает:
    - одиночный IP:      192.168.1.10
    - список IP:         192.168.1.2,192.168.1.14
    - диапазон по хостам 192.168.1.3-192.168.1.10 или 192.168.1.3-10
    - подсети:           192.168.1.0/24
    Можно комбинировать: 192.168.1.2,192.168.1.3-5,192.168.2.0/30
    """
    parts = [p.strip() for p in target.split(",") if p.strip()]
    all_ips = []

    for part in parts:
        # CIDR-подсеть
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                all_ips.extend(str(ip) for ip in net.hosts())
            except ValueError:
                continue
            continue

        # Диапазон: 192.168.1.3-192.168.1.10 или 192.168.1.3-10
        if "-" in part:
            start_str, end_str = [x.strip() for x in part.split("-", 1)]
            try:
                # вариант: 192.168.1.3-192.168.1.10
                if "." in end_str:
                    start_ip = ipaddress.ip_address(start_str)
                    end_ip = ipaddress.ip_address(end_str)
                    cur = start_ip
                    while cur <= end_ip:
                        all_ips.append(str(cur))
                        cur += 1
                else:
                    # вариант: 192.168.1.3-10 (меняется только последний октет)
                    start_ip = ipaddress.ip_address(start_str)
                    octets = start_ip.exploded.split(".")
                    base = ".".join(octets[:-1])
                    start_last = int(octets[-1])
                    end_last = int(end_str)
                    if end_last < start_last:
                        start_last, end_last = end_last, start_last
                    for host in range(start_last, end_last + 1):
                        all_ips.append(f"{base}.{host}")
            except ValueError:
                continue
            continue

        # Одиночный IP
        try:
            all_ips.append(str(ipaddress.ip_address(part)))
        except ValueError:
            continue

    return sorted(set(all_ips))


def scan_thread(target, modules, mode="quick", custom_ports=None):
    """
    В отдельном потоке:
    - разворачивает target в список IP
    - по каждому вызывает python_scanner.scan_device(...)
    - пишет результат в JSON-отчёт
    - кидает события в log_event (→ браузер и Telegram)
    """
    # старт всего прогона
    overall_t0 = time.perf_counter()
    started_wall = int(time.time())

    global STOP_SCAN
    STOP_SCAN = False

    with LOCK:
        SCAN_STATE.update(
            {
                "running": True,
                "target": target,
                "modules": modules,
                "started_at": started_wall,
                "last_message": "started",
                "mode": mode,
            }
        )

    log_event(
        f" Запуск сканирования {target} | Модули: {modules} | Режим: {mode} | custom_ports: {custom_ports}"
    )

    ips = expand_target(target)
    results = []

    for ip in ips:
        if STOP_SCAN:
            log_event(" Сканирование прервано пользователем")
            break

        log_event(f" Сканирую {ip} (mode={mode}) ...")
        try:
            # custom_ports используется только в quick режиме
            if mode == "quick":
                res = python_scanner.scan_device(
                    ip, mode=mode, modules=modules, custom_ports=custom_ports
                )
            else:
                res = python_scanner.scan_device(
                    ip, mode=mode, modules=modules, custom_ports=None
                )

            results.append(res)

            # лог по времени конкретного IP
            dur_ms = (res.get("timings") or {}).get("duration_ms")
            if isinstance(dur_ms, (int, float)):
                log_event(f"  {ip}: {int(dur_ms)} ms")

            # аналитика в лог
            risk = res.get("risk")
            high_cves = [
                c.get("cve")
                for c in (res.get("cves") or [])
                if c.get("severity", "").upper() == "HIGH"
            ]
            log_event(
                f" {ip}: alive={res.get('alive')} | risk={risk} | HIGH_CVE={','.join(high_cves) if high_cves else 'нет'}"
            )

        except Exception as e:
            log_event(f" Ошибка при сканировании {ip}: {e}")
            results.append({"ip": ip, "error": str(e)})

    # Сохраняем отчёт
    # Формат имени: scan_ГГГГ-ММ-ДД_ЧЧ-ММ-СС.json
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")  # локальное время системы
    filename = f"scan_{timestamp}.json"
    out_path = os.path.join(REPORT_DIR, filename)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # общий runtime
    overall_t1 = time.perf_counter()
    total_ms = int((overall_t1 - overall_t0) * 1000)
    log_event(f"Сканирование завершено за {total_ms} ms ({total_ms/1000:.2f} s)")

    # ВАЖНО: в лог и в Telegram уходит ТОЛЬКО имя файла отчёта
    log_event(filename)

    with LOCK:
        SCAN_STATE.update({"running": False, "last_message": "done"})


# ---------- АВТОЗАПУСК ПО РАСПИСАНИЮ ----------

def run_scheduled_scan(target, modules, mode="quick", custom_ports=None):
    """
    Запуск сканирования по расписанию.
    Проверяет, не идёт ли уже скан, чтобы не запустить два параллельно.
    """
    with LOCK:
        if SCAN_STATE["running"]:
            log_event(" Автозапуск: скан уже выполняется, пропускаю этот запуск.")
            return

    log_event(f" Автозапуск сканирования по расписанию: {target} (mode={mode})")

    th = threading.Thread(
        target=scan_thread,
        args=(target, modules, mode, custom_ports),
        daemon=True,
    )
    SCAN_STATE["thread"] = th
    th.start()


def _reschedule_auto_job():
    """
    Пересоздаёт задачу автосканирования в планировщике на основе AUTO_SCHEDULE.
    """
    global SCHEDULER, AUTO_SCHEDULE

    if SCHEDULER is None:
        return False, "Планировщик не инициализирован."

    # удаляем старую задачу, если была
    try:
        SCHEDULER.remove_job(AUTO_JOB_ID)
    except Exception:
        pass

    if not AUTO_SCHEDULE["enabled"]:
        log_event(" Планировщик: автосканирование отключено.")
        return True, "Автосканирование отключено."

    every = AUTO_SCHEDULE["every"]
    unit = AUTO_SCHEDULE["unit"]
    target = AUTO_SCHEDULE["target"]
    modules = AUTO_SCHEDULE["modules"]
    mode = AUTO_SCHEDULE["mode"] or "quick"
    custom_ports = AUTO_SCHEDULE["custom_ports"]

    if not target:
        AUTO_SCHEDULE["enabled"] = False
        return False, "Цель не задана."
    if not every or every <= 0:
        AUTO_SCHEDULE["enabled"] = False
        return False, "Период должен быть положительным числом."
    if unit not in ("minutes", "hours", "days", "weeks"):
        AUTO_SCHEDULE["enabled"] = False
        return False, "Неизвестная единица времени."

    trigger_kwargs = {
        "id": AUTO_JOB_ID,
        "replace_existing": True,
        "args": (target, modules, mode, custom_ports),
    }

    if unit == "minutes":
        trigger_kwargs["minutes"] = every
    elif unit == "hours":
        trigger_kwargs["hours"] = every
    elif unit == "days":
        trigger_kwargs["days"] = every
    elif unit == "weeks":
        trigger_kwargs["weeks"] = every

    SCHEDULER.add_job(run_scheduled_scan, "interval", **trigger_kwargs)
    msg = f"Автосканирование включено: каждые {every} {unit}, цель {target}."
    log_event(" Планировщик: " + msg)
    return True, msg


def init_scheduler():
    """
    Инициализация фонового планировщика задач сканирования.
    """
    global SCHEDULER
    scheduler = BackgroundScheduler()
    scheduler.start()
    SCHEDULER = scheduler
    log_event(" Планировщик запущен (задач по умолчанию нет).")
    return scheduler


# ---------- API ----------

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json() or {}
    target = data.get("target")
    modules = data.get("modules", [])
    mode = data.get("mode", "quick")         # quick|special|full
    custom_ports = data.get("custom_ports")  # например "22,80,1000-1010"

    if not target:
        return {"ok": False, "message": "target required"}, 400
    if SCAN_STATE["running"]:
        return {"ok": False, "message": "скан уже запущен"}, 409

    # предупреждение для full-скана
    if mode == "full":
        log_event(" Full scan (1..65535). Это может занять очень много времени.")

    th = threading.Thread(
        target=scan_thread, args=(target, modules, mode, custom_ports), daemon=True
    )
    SCAN_STATE["thread"] = th
    th.start()
    return {"ok": True, "message": f"Сканирование начато (mode={mode})"}


@app.route("/api/schedule", methods=["GET", "POST"])
def api_schedule():
    global AUTO_SCHEDULE
    if request.method == "GET":
        if AUTO_SCHEDULE["enabled"]:
            status_text = (
                f"включено: каждые {AUTO_SCHEDULE['every']} {AUTO_SCHEDULE['unit']} "
                f"(цель {AUTO_SCHEDULE['target']})"
            )
        else:
            status_text = "отключено"
        resp = AUTO_SCHEDULE.copy()
        resp["status_text"] = status_text
        return jsonify(resp)

    data = request.get_json() or {}
    enabled = bool(data.get("enabled"))
    every = data.get("every")
    try:
        every = int(every) if every is not None else None
    except (TypeError, ValueError):
        every = None

    unit = data.get("unit") or "hours"
    target = (data.get("target") or "").strip() or None
    mode = data.get("mode") or "quick"
    custom_ports = data.get("custom_ports") or None
    modules = data.get("modules") or []

    if enabled:
        if not target:
            return jsonify({"ok": False, "message": "Для включения автосканирования нужно указать цель."}), 400
        if not every or every <= 0:
            return jsonify({"ok": False, "message": "Период должен быть положительным числом."}), 400

    AUTO_SCHEDULE.update(
        {
            "enabled": enabled,
            "every": every,
            "unit": unit,
            "target": target,
            "mode": mode,
            "custom_ports": custom_ports,
            "modules": modules,
        }
    )

    ok, msg = _reschedule_auto_job()
    if AUTO_SCHEDULE["enabled"] and ok:
        status_text = (
            f"включено: каждые {AUTO_SCHEDULE['every']} {AUTO_SCHEDULE['unit']} "
            f"(цель {AUTO_SCHEDULE['target']})"
        )
    elif AUTO_SCHEDULE["enabled"] and not ok:
        status_text = "ошибка в параметрах расписания"
    else:
        status_text = "отключено"

    return jsonify(
        {
            "ok": ok,
            "message": msg,
            "enabled": AUTO_SCHEDULE["enabled"],
            "every": AUTO_SCHEDULE["every"],
            "unit": AUTO_SCHEDULE["unit"],
            "status_text": status_text,
        }
    )


@app.route("/api/reports")
def api_reports():
    files = sorted(
        [os.path.basename(p) for p in glob.glob(os.path.join(REPORT_DIR, "*.json"))],
        reverse=True,
    )
    return jsonify([{"name": f} for f in files])


@app.route("/reports/<name>")
def rep(name):
    p = os.path.join(REPORT_DIR, name)
    if not os.path.exists(p):
        log_event(f"DEBUG: report not found: {p}")
        abort(404)
    return send_from_directory(REPORT_DIR, name)


@app.route("/api/stop", methods=["POST"])
def api_stop():
    global STOP_SCAN
    STOP_SCAN = True
    log_event(" Получена команда остановки сканирования.")
    return jsonify({"ok": True, "message": "Сканирование остановлено."})


@app.route("/api/system_load")
def api_system_load():
    return jsonify(get_system_metrics())


if __name__ == "__main__":
    db.init_db()
    init_scheduler()  # запускаем планировщик
    print("Сканер запущен")
    # важно отключить reloader, чтобы не было двойного планировщика
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
