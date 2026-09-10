#!/usr/bin/env python3
"""dcap-runner: периодический сканер списка сетевых ресурсов поверх dcap-scan.

Конфигурация через переменные окружения:
  RESOURCE_LIST  - файл со списком ресурсов (по умолчанию <MANAGER_DIR>/conf/list.txt,
                   по одному ресурсу на строку, '#' - комментарий)
  MANAGER_DIR    - рабочий каталог с состоянием (по умолчанию /manager)
  MOUNT_ROOT     - корень точек монтирования SMB-ресурсов (по умолчанию /mnt/shares)
  SCHEDULE       - окна работы вида "HH:MM-HH:MM;HH:MM-HH:MM" или "always"
                   (по умолчанию "always" - работает, пока не остановят)
SCAN_LOOP      - "1" - в окне запускать новые проходы сразу после завершения
                    (по умолчанию "0" - один полный проход на одно окно)
   RUN_ONCE       - "1" - один полный проход по списку, затем завершение работы
                    (по умолчанию "0" - работа, пока не остановят; удобно с SCHEDULE)
  UNIFIED_LOG    - единый лог находок (по умолчанию <MANAGER_DIR>/unified.log)
  SCANNER        - путь к бинарю сканера (по умолчанию /usr/local/bin/dcap-scan)
  SCAN_THREADS   - число потоков сканера (по умолчанию 4)
  SCAN_ARGS      - дополнительные флаги сканера через пробел
  SMB_USER/SMB_PASS/SMB_PASS_FILE/SMB_DOMAIN/SMB_OPTS - учётные данные для mount.cifs

Ресурс считаем SMB, если строка начинается с "//" или "\"; иначе это уже
доступный путь (bind-mounted каталог) и маунт не нужен.
Управление: <MANAGER_DIR>/control/pause - пауза, control/stop - прервать проход.
"""
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime


def env(key, default):
    return os.environ.get(key, default)


def log(msg):
    print(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}", flush=True)


MANAGER = env("MANAGER_DIR", "/manager")
MOUNT_ROOT = env("MOUNT_ROOT", "/mnt/shares")
LIST = env("RESOURCE_LIST", "") or os.path.join(MANAGER, "conf", "list.txt")
SCHEDULE = env("SCHEDULE", "always")
SCAN_LOOP = env("SCAN_LOOP", "0") == "1"
RUN_ONCE = env("RUN_ONCE", "0") == "1"
SCANNER = env("SCANNER", "/usr/local/bin/dcap-scan")
SCAN_THREADS = int(env("SCAN_THREADS", "4"))
SCAN_ARGS = env("SCAN_ARGS", "").split()
UNIFIED = env("UNIFIED_LOG", os.path.join(MANAGER, "unified.log"))
SMB_USER = env("SMB_USER", "")
SMB_PASS = env("SMB_PASS", "")
if env("SMB_PASS_FILE", "") and os.path.isfile(env("SMB_PASS_FILE", "")):
    SMB_PASS = open(env("SMB_PASS_FILE", ""), encoding="utf-8").read().strip()
SMB_DOMAIN = env("SMB_DOMAIN", "")
SMB_OPTS = env("SMB_OPTS", ",noperm,vers=3.0,cache=none")

STATE_DIR = os.path.join(MANAGER, "state")
REPORT_DIR = os.path.join(MANAGER, "report")
CONTROL_DIR = os.path.join(MANAGER, "control")
PAUSE_FILE = os.path.join(CONTROL_DIR, "pause")
STOP_FILE = os.path.join(CONTROL_DIR, "stop")
CYCLE_FILE = os.path.join(MANAGER, "cycle.json")

stop_requested = False


def on_signal(signum, frame):
    global stop_requested
    stop_requested = True


signal.signal(signal.SIGTERM, on_signal)
signal.signal(signal.SIGINT, on_signal)


def unescape_mounts(s):
    return s.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")


def slug_for(url):
    clean = url.rstrip("/\\")
    name = clean.replace("\\", "/").rsplit("/", 1)[-1] or "share"
    safe = []
    for ch in name:
        if ch.isascii() and (ch.isalnum() or ch in "._-"):
            safe.append(ch)
        else:
            safe.append("_")
    safe = "".join(safe).strip("._")[:48] or "share"
    return f"{safe}_{hashlib.sha256(url.encode('utf-8')).hexdigest()[:8]}"


def is_smb(url):
    return url.startswith("//") or url.startswith("\\\\")


def load_resources(path):
    resources = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip().lstrip("\ufeff")
            if not line or line.startswith("#"):
                continue
            resources.append(line)
    return resources


def is_mounted(target):
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == target:
                    return unescape_mounts(parts[0])
    except OSError:
        pass
    return None


def ensure_mounted(url):
    if not is_smb(url):
        if not os.path.isdir(url):
            raise RuntimeError(f"каталог не существует: {url}")
        return url, "локальный путь"
    mount = os.path.join(MOUNT_ROOT, slug_for(url))
    src = is_mounted(mount)
    want = url.rstrip("/")
    if src:
        if src.endswith(want) or want.endswith(src.split("//")[-1]) and src == want:
            return mount, "уже смонтирован"
        log(f"точка {mount} занята другим источником ({src}), перемонтирую")
        subprocess.run(["umount", mount], check=False)
    os.makedirs(mount, exist_ok=True)
    opts = f"username={SMB_USER},password={SMB_PASS},{SMB_OPTS}"
    if SMB_DOMAIN:
        opts += f",domain={SMB_DOMAIN}"
    opts += ",ro"
    result = subprocess.run(
        ["mount", "-t", "cifs", url, mount, "-o", opts],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"mount {url}: {result.stderr.strip()}")
    return mount, "смонтирован сейчас"


def umount_share(scan_root, slug):
    subprocess.run(["umount", scan_root], check=False)
    log(f"  [{slug}] размонтировал {scan_root}")


def parse_schedule(s):
    s = (s or "").strip().lower()
    if s in ("", "always", "-", "none"):
        return None
    windows = []
    for part in s.replace(",", ";").split(";"):
        part = part.strip()
        if not part:
            continue
        a, b = part.split("-")
        def minutes(tok):
            hh, mm = tok.strip().split(":")
            return int(hh) * 60 + int(mm)
        windows.append((minutes(a), minutes(b)))
    return windows


def in_window(windows, now):
    if windows is None:
        return True
    t = now.hour * 60 + now.minute
    for a, b in windows:
        if a == b:
            continue
        if a < b:
            if a <= t < b:
                return True
        elif t >= a or t < b:
            return True
    return False


def load_cycle():
    if os.path.exists(CYCLE_FILE):
        try:
            with open(CYCLE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None


def save_cycle(c):
    os.makedirs(MANAGER, exist_ok=True)
    tmp = CYCLE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(c, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CYCLE_FILE)


def new_cycle(prev):
    return {
        "cycle": (prev["cycle"] + 1) if prev else 1,
        "started": datetime.now().isoformat(timespec="seconds"),
        "resources": {},
        "completed": False,
    }


RE_FILE_HEADER = re.compile(r"# Файлов:\s+(\d+)\s+скан")
RE_FIND_HEADER = re.compile(r"# Находок:\s+(\d+)")
RE_FIND_LINE = re.compile(r"^(.+?):(\d+)\s*::\s*(.+?)\s+\(conf\s+([\d.]+)\)\s*$")
RE_PROGRESS = re.compile(r"^\[i\] Прогресс:")
RE_ITOGO = re.compile(
    r"^\[i\] Итого по ресурсу: файлов (\d+)(?: \([^)]*\))?, с находками (\d+), "
    r"без находок (\d+), с ошибками (\d+), пропущено (\d+)$")


def aggregate(url, slug, cycle_no, scan_root, report_path):
    with open(report_path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    mf = RE_FILE_HEADER.search(text)
    mh = RE_FIND_HEADER.search(text)
    files = int(mf.group(1)) if mf else 0
    find_count = int(mh.group(1)) if mh else 0
    findings = []
    cur = None
    in_find = False
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("[НАХОДКИ]"):
            in_find = True
            continue
        if in_find and s.startswith("["):
            in_find = False
            break
        if not in_find or not s:
            continue
        m = RE_FIND_LINE.match(s)
        if m:
            if cur:
                findings.append(cur)
            path, ln, sub, conf = m.groups()
            rel = path[len(scan_root):] if path.startswith(scan_root) else path
            cur = {"path": rel, "line": ln, "sub": sub, "conf": conf,
                   "value": "", "context": ""}
        elif cur is not None:
            if s.startswith("value:"):
                cur["value"] = s[6:].strip()
            elif s.startswith("context:"):
                cur["context"] = s[8:].strip()
    if cur:
        findings.append(cur)
    os.makedirs(os.path.dirname(UNIFIED), exist_ok=True)
    with open(UNIFIED, "a", encoding="utf-8") as f:
        f.write(f"--- {url}  slug={slug}  цикл={cycle_no}  "
                f"файлов={files}  находок={find_count} ---\n")
        for fd in findings:
            value = " ".join(fd["value"].split())
            context = " ".join(fd["context"].split())
            ts = datetime.now().isoformat(timespec="seconds")
            f.write(f"{ts}\t{url}\t{fd['path']}:{fd['line']}\t"
                    f"{fd['sub']}\t{fd['conf']}\t{value}\t{context}\n")
    return files, find_count


def send_stop(proc):
    try:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    except ProcessLookupError:
        pass


def scan_resource(url, scan_root, cycle_no, slug):
    report_base = os.path.join(REPORT_DIR, f"{slug}.c{cycle_no}.log")
    statef = os.path.join(STATE_DIR, f"{slug}.c{cycle_no}.tsv")
    while True:
        args = ([SCANNER, scan_root, report_base, str(SCAN_THREADS)]
                + SCAN_ARGS + ["--state", statef])
        log(f"  [{slug}] сканирую {url}")
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace")
        lines = []
        res_totals = None

        def read_loop():
            nonlocal res_totals
            for raw in proc.stdout:
                line = raw.rstrip("\r\n")
                lines.append(line)
                if line.startswith("[i] Прогресс"):
                    log(f"  [{slug}] {line}")
                elif line.startswith("[i] Итого по ресурсу"):
                    log(f"  [{slug}] {line}")
                    m = RE_ITOGO.match(line)
                    if m:
                        res_totals = [int(g) for g in m.groups()]

        reader = threading.Thread(target=read_loop, daemon=True)
        reader.start()
        outcome = None
        while proc.poll() is None:
            if stop_requested or os.path.exists(STOP_FILE):
                log(f"  [{slug}] stop: останавливаю сканирование")
                send_stop(proc)
                outcome = "stop"
                break
            if os.path.exists(PAUSE_FILE):
                log(f"  [{slug}] пауза: останавливаюсь после текущего файла")
                send_stop(proc)
                outcome = "paused"
                break
            time.sleep(1)
        reader.join(timeout=5)
        out = "\n".join(lines) + "\n"
        if outcome is None and (stop_requested or os.path.exists(STOP_FILE)):
            log("  stop: прерывание застало уже завершившийся скан — считаю остановом")
            outcome = "stop"
        if outcome == "stop":
            return None, None
        if outcome == "paused":
            log(f"  [{slug}] пауза, жду снятия (control/pause)")
            while os.path.exists(PAUSE_FILE) and not stop_requested:
                time.sleep(2)
            if stop_requested:
                return None, None
            log(f"  [{slug}] пауза снята, продолжаю с места останова")
            continue
        if proc.returncode is not None and proc.returncode < 0:
            log(f"  [{slug}] скан прерван сигналом (код {proc.returncode}) — считаю остановом, "
                f"state сохранён, продолжу с места останова")
            return None, None
        if proc.returncode not in (0, 2):
            raise RuntimeError(f"сканер завершился с кодом {proc.returncode}")
        m = re.search(r"Лог\s*:\s*(\S+)", out)
        report_path = m.group(1).strip() if m else report_base
        return report_path, res_totals


def record_done(cycle, slug, files, find_count):
    cycle["resources"][slug] = {
        "status": "done",
        "files": files,
        "findings": find_count,
    }
    save_cycle(cycle)


def run_pass(cycle, resources):
    n = len(resources)
    totals = [0, 0, 0, 0, 0]
    pass_t0 = time.monotonic()
    for i, url in enumerate(resources, 1):
        if stop_requested or os.path.exists(STOP_FILE):
            log("остановка между ресурсами")
            return False
        slug = slug_for(url)
        st = cycle["resources"].get(slug, {}).get("status")
        if st == "done":
            saved = cycle["resources"][slug].get("files", 0)
            log(f"  ресурс {i}/{n}: завершён в этом проходе ({url}), файлов {saved}")
            continue
        if st == "error":
            log(f"  ресурс {i}/{n}: ошибка в этом проходе ({url})")
            continue
        log(f"  ресурс {i}/{n}: {url}")
        try:
            scan_root, note = ensure_mounted(url)
        except RuntimeError as exc:
            log(f"    {url}: {exc}; пропускаю")
            cycle["resources"][slug] = {"status": "error", "reason": str(exc)}
            save_cycle(cycle)
            continue
        log(f"    [{slug}] {url} -> {scan_root} ({note})")
        s_t0 = time.monotonic()
        mounted_now = note == "смонтирован сейчас"
        try:
            report_path, res_totals = scan_resource(url, scan_root, cycle["cycle"], slug)
            if report_path is None:
                return False
            if os.path.exists(report_path):
                files, find_count = aggregate(
                    url, slug, cycle["cycle"], scan_root.rstrip("/") + "/", report_path)
                record_done(cycle, slug, files, find_count)
                s_el = max(time.monotonic() - s_t0, 0.001)
                log(f"    [{slug}] готово: файлов {files}, находок {find_count} ({files / s_el:.1f}/с)")
                if res_totals:
                    for k in range(5):
                        totals[k] += res_totals[k]
        except RuntimeError as exc:
            log(f"    {url}: {exc}; пропускаю")
            cycle["resources"][slug] = {"status": "error", "reason": str(exc)}
            save_cycle(cycle)
            continue
        finally:
            if mounted_now:
                umount_share(scan_root, slug)
        done_now = sum(
            1 for r in resources
            if cycle["resources"].get(slug_for(r), {}).get("status") in ("done", "error"))
        log(f"  обработано ресурсов {done_now}/{n}, осталось {n - done_now}")
        if done_now:
            pass_el = max(time.monotonic() - pass_t0, 0.001)
            log(f"  итого по проходу: файлов {totals[0]} ({totals[0] / pass_el:.1f}/с), "
                f"с находками {totals[1]}, без находок {totals[2]}, "
                f"с ошибками {totals[3]}, пропущено {totals[4]}")
    cycle["completed"] = True
    cycle["finished"] = datetime.now().isoformat(timespec="seconds")
    save_cycle(cycle)
    pass_el = max(time.monotonic() - pass_t0, 0.001)
    if totals[0]:
        log(f"  итог прохода: ресурсов {n}, файлов {totals[0]} ({totals[0] / pass_el:.1f}/с), "
            f"с находками {totals[1]}, без находок {totals[2]}, "
            f"с ошибками {totals[3]}, пропущено {totals[4]}")
    else:
        log("  итог прохода: ресурсы не сканировались (пропущены или ошибки)")
    return True


def main():
    global stop_requested
    for d in (STATE_DIR, REPORT_DIR, CONTROL_DIR, MOUNT_ROOT, os.path.dirname(LIST)):
        os.makedirs(d, exist_ok=True)
    if os.path.exists(STOP_FILE):
        log("control/stop найден, снимаю (одноразовое прерывание)")
        os.remove(STOP_FILE)
    if not os.path.exists(LIST):
        log(f"ОШИБКА: список ресурсов не найден: {LIST}")
        sys.exit(2)
    resources = load_resources(LIST)
    if not resources:
        log("ОШИБКА: список ресурсов пуст")
        sys.exit(2)
    windows = parse_schedule(SCHEDULE)
    if windows is None or not windows:
        windows = None
    continuous = windows is None
    cycle = load_cycle()
    if cycle is None or cycle.get("completed"):
        cycle = new_cycle(cycle)
        log(f"новый цикл {cycle['cycle']}; ресурсов: {len(resources)}")
    else:
        log(f"продолжаю цикл {cycle['cycle']} (незавершён)")
    save_cycle(cycle)

    served_window = None
    while not stop_requested:
        now = datetime.now()
        if os.path.exists(STOP_FILE):
            log("control/stop: прерываю проход")
            break
        if os.path.exists(PAUSE_FILE):
            log("control/pause: жду снятия паузы")
            while os.path.exists(PAUSE_FILE) and not stop_requested:
                time.sleep(2)
            continue
        tag = 0 if continuous else (1 if in_window(windows, now) else -1)
        if tag == -1:
            served_window = None
            time.sleep(30)
            continue
        if (not continuous and not SCAN_LOOP
                and served_window == tag and cycle.get("completed")):
            time.sleep(60)
            continue
        if cycle.get("completed"):
            cycle = new_cycle(cycle)
            save_cycle(cycle)
            log(f"новый цикл {cycle['cycle']}")
        served_window = tag
        ok = run_pass(cycle, resources)
        if not ok:
            log("проход прерван; при следующем запуске продолжу с места останова")
            break
        log(f"цикл {cycle['cycle']} завершён")
        if RUN_ONCE:
            log("RUN_ONCE=1: один проход по списку выполнен, завершаю работу")
            break
        if continuous and not cycle.get("completed"):
            pass
    log("завершение работы")


if __name__ == "__main__":
    main()