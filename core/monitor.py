import psutil, time

def get_system_metrics():
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "mem_percent": psutil.virtual_memory().percent,
        "threads": psutil.Process().num_threads(),
        "uptime_sec": round(time.time() - psutil.boot_time())
    }
