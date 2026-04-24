#!/usr/bin/env python3
# +═════════════════════════════════════════════════════════════════════════+
# ║                   MK VLESS CHECKER (standalone)                         ║
# ║        Fetch subscription URLs -> parse VLESS -> test ping/speed        ║
# ║                     Output: vless-list.txt                              ║
# +═════════════════════════════════════════════════════════════════════════+
# Based on v2rayChecker.py by MKultra69.

import base64
import json
import os
import random
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    requests = None

try:
    import xray_installer
    XRAY_INSTALLER_AVAILABLE = True
except Exception:
    XRAY_INSTALLER_AVAILABLE = False


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_FILE = os.path.join(SCRIPT_DIR, "source.json")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "vless-list.txt")

CFG = {
    "fetch_timeout": 15,
    "fetch_threads": 20,
    "start_port": 21080,
    "batch_size": 40,
    "max_concurrent_tests": 40,
    "ping_timeout": 6,
    "ping_url": "https://www.google.com/generate_204",
    "check_speed": True,
    "speed_timeout": 8,
    "speed_connect_timeout": 4,
    "speed_max_mb": 3,
    "speed_min_kb": 20,
    "speed_targets": [
        "https://speed.cloudflare.com/__down?bytes=10000000",
        "http://speedtest.tele2.net/10MB.zip",
        "https://proof.ovh.net/files/10Mb.dat",
    ],
    "core_startup_timeout": 6.0,
    "sort_by": "ping",
}

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"


def log(msg):
    try:
        print(msg, flush=True)
    except Exception:
        pass


# +═════════════════════════════════════════════════════════════════════════+
# ║                           Sources loading                               ║
# +═════════════════════════════════════════════════════════════════════════+

def load_sources():
    default_sources = [
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/vless.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vless",
        "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt",
    ]
    try:
        if not os.path.exists(SOURCE_FILE):
            with open(SOURCE_FILE, "w", encoding="utf-8") as f:
                json.dump(default_sources, f, indent=4, ensure_ascii=False)
            log(f"[INFO] Создан файл {SOURCE_FILE} с дефолтными источниками.")
            return default_sources
        with open(SOURCE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            urls = []
            for v in data.values():
                if isinstance(v, list):
                    urls.extend(v)
                elif isinstance(v, str):
                    urls.append(v)
            return [u for u in urls if isinstance(u, str) and u.strip()]
        if isinstance(data, list):
            return [u for u in data if isinstance(u, str) and u.strip()]
    except Exception as e:
        log(f"[WARN] Ошибка загрузки {SOURCE_FILE}: {e}. Используем дефолт.")
    return default_sources


def fetch_one_source(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=CFG["fetch_timeout"]) as r:
            raw = r.read()
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            text = raw.decode(errors="ignore")
        return text
    except Exception:
        return ""


def try_decode_base64(text):
    try:
        s = "".join(text.split())
        if not s or len(s) < 16:
            return None
        if not re.fullmatch(r"[A-Za-z0-9+/=_\-]+", s):
            return None
        s = s.replace("-", "+").replace("_", "/")
        pad = (-len(s)) % 4
        s += "=" * pad
        decoded = base64.b64decode(s, validate=False).decode("utf-8", errors="ignore")
        if "vless://" in decoded or "vmess://" in decoded:
            return decoded
    except Exception:
        pass
    return None


def extract_vless_lines(text):
    if not text:
        return []
    decoded = try_decode_base64(text)
    if decoded:
        text = decoded
    lines = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.lower().startswith("vless://"):
            lines.append(s)
    return lines


def gather_vless_configs(sources):
    seen = set()
    configs = []
    log(f"[INFO] Источников: {len(sources)}. Загружаем...")
    with ThreadPoolExecutor(max_workers=CFG["fetch_threads"]) as ex:
        futures = {ex.submit(fetch_one_source, u): u for u in sources}
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                text = fut.result()
            except Exception:
                text = ""
            found = extract_vless_lines(text)
            added = 0
            for link in found:
                key = link.split("#", 1)[0].strip()
                if key and key not in seen:
                    seen.add(key)
                    configs.append(link)
                    added += 1
            log(f"[SRC] {url} -> {added} новых (всего уникальных: {len(configs)})")
    log(f"[INFO] Всего уникальных VLESS: {len(configs)}")
    return configs


# +═════════════════════════════════════════════════════════════════════════+
# ║                           VLESS parsing                                 ║
# +═════════════════════════════════════════════════════════════════════════+

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
FLOW_ALLOWED = {"", "xtls-rprx-vision"}


def parse_vless(url):
    try:
        if not url or not url.lower().startswith("vless://"):
            return None
        main_part = url.split("#", 1)[0]
        m = re.match(r"vless://([^@]+)@([^:]+):(\d+)(\?[^#]*)?", main_part)
        if not m:
            return None
        uuid = m.group(1).strip()
        address = m.group(2).strip()
        try:
            port = int(m.group(3))
        except Exception:
            return None
        if not UUID_RE.match(uuid):
            return None
        if port <= 0 or port > 65535:
            return None
        if not address:
            return None

        params = {}
        if m.group(4):
            q = m.group(4)[1:]
            try:
                params = urllib.parse.parse_qs(q, keep_blank_values=True)
            except Exception:
                params = {}

        def p(key, default=""):
            v = params.get(key, [default])
            return (v[0] if v else default).strip()

        net_type = p("type", "tcp").lower() or "tcp"
        security = p("security", "none").lower()
        if security not in ("tls", "reality", "none", "xtls"):
            security = "none"
        if security == "xtls":
            security = "tls"

        flow = p("flow", "").lower()
        if flow not in FLOW_ALLOWED:
            flow = ""
        if flow and security not in ("tls", "reality"):
            flow = ""

        pbk = p("pbk", "")
        sid = p("sid", "")
        if security == "reality" and not pbk:
            return None

        return {
            "address": address,
            "port": port,
            "uuid": uuid,
            "net": net_type,
            "security": security,
            "flow": flow,
            "sni": p("sni", ""),
            "host": p("host", ""),
            "path": urllib.parse.unquote(p("path", "")),
            "fp": p("fp", "chrome") or "chrome",
            "alpn": p("alpn", ""),
            "pbk": pbk,
            "sid": sid,
            "serviceName": p("serviceName", ""),
            "mode": p("mode", ""),
        }
    except Exception:
        return None


# +═════════════════════════════════════════════════════════════════════════+
# ║                       Xray outbound builder                             ║
# +═════════════════════════════════════════════════════════════════════════+

def build_outbound(conf, tag):
    try:
        net = conf["net"]
        security = conf["security"]

        stream = {"network": net, "security": security}

        tls_settings = {
            "serverName": conf["sni"] or conf["host"] or conf["address"],
            "allowInsecure": True,
            "fingerprint": conf["fp"] or "chrome",
        }
        if conf["alpn"]:
            tls_settings["alpn"] = [a for a in conf["alpn"].split(",") if a]

        if security == "tls":
            stream["tlsSettings"] = tls_settings
        elif security == "reality":
            sid = conf["sid"]
            if len(sid) % 2 != 0:
                sid = ""
            stream["realitySettings"] = {
                "publicKey": conf["pbk"],
                "shortId": sid,
                "serverName": tls_settings["serverName"],
                "fingerprint": tls_settings["fingerprint"],
                "spiderX": "/",
            }

        if net == "ws":
            ws = {"path": conf["path"] or "/"}
            if conf["host"]:
                ws["headers"] = {"Host": conf["host"]}
            stream["wsSettings"] = ws
        elif net == "grpc":
            stream["grpcSettings"] = {
                "serviceName": conf["serviceName"] or "",
                "multiMode": (conf["mode"] == "multi"),
            }
        elif net == "httpupgrade":
            stream["httpupgradeSettings"] = {
                "path": conf["path"] or "/",
                "host": conf["host"] or "",
            }
        elif net in ("http", "h2"):
            stream["network"] = "http"
            stream["httpSettings"] = {
                "path": conf["path"] or "/",
                "host": [conf["host"]] if conf["host"] else [],
            }
        elif net == "xhttp":
            stream["xhttpSettings"] = {
                "path": conf["path"] or "/",
                "host": conf["host"] or "",
                "mode": "auto",
            }
        elif net == "tcp":
            pass
        else:
            stream["network"] = "tcp"

        user = {"id": conf["uuid"], "encryption": "none"}
        if conf["flow"]:
            user["flow"] = conf["flow"]

        return {
            "protocol": "vless",
            "tag": tag,
            "settings": {
                "vnext": [{
                    "address": conf["address"],
                    "port": conf["port"],
                    "users": [user],
                }]
            },
            "streamSettings": stream,
        }
    except Exception:
        return None


def build_batch_config(parsed_entries, start_port):
    inbounds, outbounds, rules = [], [], []
    mapping = []
    for i, (url, conf) in enumerate(parsed_entries):
        port = start_port + i
        in_tag = f"in_{port}"
        out_tag = f"out_{port}"
        ob = build_outbound(conf, out_tag)
        if not ob:
            continue
        inbounds.append({
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "tag": in_tag,
            "settings": {"udp": False, "auth": "noauth"},
        })
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})
        mapping.append((url, port))

    if not mapping:
        return None, []

    full = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    return full, mapping


# +═════════════════════════════════════════════════════════════════════════+
# ║                         Xray core management                            ║
# +═════════════════════════════════════════════════════════════════════════+

def ensure_xray():
    candidates = []
    if XRAY_INSTALLER_AVAILABLE:
        try:
            path = xray_installer.ensure_xray_installed({"autoinstall_xray": True, "xray_version": "latest"})
            if path and os.path.exists(path):
                return path
        except Exception as e:
            log(f"[WARN] xray_installer недоступен: {e}")

    is_win = sys.platform.startswith("win")
    binary = "xray.exe" if is_win else "xray"
    candidates.extend([
        os.path.join(SCRIPT_DIR, "bin", binary),
        os.path.join(SCRIPT_DIR, binary),
        binary,
    ])
    for path in candidates:
        try:
            if os.path.isabs(path) and os.path.exists(path):
                return path
            result = subprocess.run([path, "version"], capture_output=True, timeout=5)
            if result.returncode == 0:
                return path
        except Exception:
            continue
    return None


def start_xray(core_path, config_path):
    try:
        if not sys.platform.startswith("win"):
            try:
                st = os.stat(core_path)
                os.chmod(core_path, st.st_mode | stat.S_IXEXEC | stat.S_IXUSR)
            except Exception:
                pass
        cmd = [core_path, "run", "-c", config_path] if "xray" in os.path.basename(core_path).lower() else [core_path, "-c", config_path]
        return subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
    except Exception as e:
        log(f"[ERROR] Не удалось запустить xray: {e}")
        return None


def kill_proc(proc):
    if not proc:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def is_port_open(port, host="127.0.0.1"):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def wait_for_core(proc, mapping, timeout):
    start = time.time()
    first_port = mapping[0][1] if mapping else None
    while time.time() - start < timeout:
        try:
            if proc.poll() is not None:
                return False
            if first_port and is_port_open(first_port):
                return True
        except Exception:
            return False
        time.sleep(0.15)
    return False


# +═════════════════════════════════════════════════════════════════════════+
# ║                         Proxy testing logic                             ║
# +═════════════════════════════════════════════════════════════════════════+

def check_ping(local_port):
    if not requests:
        return 0
    proxies = {
        "http": f"socks5h://127.0.0.1:{local_port}",
        "https": f"socks5h://127.0.0.1:{local_port}",
    }
    try:
        start = time.time()
        r = requests.get(
            CFG["ping_url"],
            proxies=proxies,
            timeout=CFG["ping_timeout"],
            verify=False,
        )
        elapsed = int((time.time() - start) * 1000)
        if r.status_code < 400:
            return max(elapsed, 1)
    except Exception:
        pass
    return 0


def check_speed(local_port):
    if not requests:
        return 0.0
    proxies = {
        "http": f"socks5h://127.0.0.1:{local_port}",
        "https": f"socks5h://127.0.0.1:{local_port}",
    }
    targets = list(CFG["speed_targets"])
    random.shuffle(targets)
    limit_bytes = CFG["speed_max_mb"] * 1024 * 1024
    headers = {"User-Agent": UA, "Accept": "*/*", "Connection": "keep-alive"}

    for url in targets:
        try:
            with requests.get(
                url,
                proxies=proxies,
                headers=headers,
                stream=True,
                timeout=(CFG["speed_connect_timeout"], CFG["speed_timeout"]),
                verify=False,
            ) as r:
                if r.status_code >= 400:
                    continue
                total = 0
                start = time.time()
                for chunk in r.iter_content(chunk_size=32768):
                    if chunk:
                        total += len(chunk)
                    if (time.time() - start) >= CFG["speed_timeout"] or total >= limit_bytes:
                        break
                duration = max(time.time() - start, 0.1)
                if total < CFG["speed_min_kb"] * 1024:
                    continue
                mbps = (total / duration) / 125000.0
                return round(mbps, 2)
        except Exception:
            continue
    return 0.0


def test_single(url, port):
    try:
        ping_ms = check_ping(port)
        if not ping_ms:
            return None
        speed_mbps = 0.0
        if CFG["check_speed"]:
            try:
                speed_mbps = check_speed(port)
            except Exception:
                speed_mbps = 0.0
        return (url, ping_ms, speed_mbps)
    except Exception:
        return None


def test_batch(core_path, parsed_entries, start_port):
    results = []
    try:
        config_obj, mapping = build_batch_config(parsed_entries, start_port)
        if not config_obj or not mapping:
            return results
    except Exception as e:
        log(f"[WARN] Не удалось собрать батч конфиг: {e}")
        return results

    tmp_path = None
    proc = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="mk_vless_", suffix=".json", dir=SCRIPT_DIR)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config_obj, f)

        proc = start_xray(core_path, tmp_path)
        if not proc:
            return results

        if not wait_for_core(proc, mapping, CFG["core_startup_timeout"]):
            log(f"[WARN] Ядро не стартовало для батча {start_port} (пропускаем {len(mapping)} конфигов)")
            return results

        max_workers = min(len(mapping), CFG["max_concurrent_tests"])
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(test_single, url, port) for (url, port) in mapping]
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                except Exception:
                    r = None
                if r:
                    url, ping_ms, speed = r
                    sp = f" | {speed:>5} Mbps" if CFG["check_speed"] else ""
                    try:
                        host = url.split("@", 1)[1].split("?", 1)[0].split("#", 1)[0]
                    except Exception:
                        host = "?"
                    log(f"[LIVE] {host:<30} | {ping_ms:>4} ms{sp}")
                    results.append(r)
    except Exception as e:
        log(f"[WARN] Ошибка в батче {start_port}: {e}")
    finally:
        kill_proc(proc)
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
    return results


# +═════════════════════════════════════════════════════════════════════════+
# ║                                Main                                     ║
# +═════════════════════════════════════════════════════════════════════════+

def main():
    log("=" * 60)
    log("  MK VLESS CHECKER - standalone subscription validator")
    log("=" * 60)

    if requests is None:
        log("[ERROR] Модуль 'requests' не установлен. Установите: pip install requests")
        return 1

    sources = load_sources()
    if not sources:
        log("[ERROR] Нет источников в source.json.")
        return 1

    configs = []
    try:
        configs = gather_vless_configs(sources)
    except Exception as e:
        log(f"[ERROR] Сбор конфигов провалился: {e}")

    if not configs:
        log("[ERROR] Не найдено ни одного VLESS. Завершаем.")
        return 1

    parsed = []
    for link in configs:
        try:
            conf = parse_vless(link)
            if conf:
                parsed.append((link, conf))
        except Exception:
            continue
    log(f"[INFO] Распарсено валидных VLESS: {len(parsed)} (отбраковано {len(configs) - len(parsed)})")

    if not parsed:
        log("[ERROR] Ни один конфиг не прошёл парсинг.")
        return 1

    core_path = None
    try:
        core_path = ensure_xray()
    except Exception as e:
        log(f"[ERROR] Не удалось обеспечить xray: {e}")
    if not core_path:
        log("[ERROR] Xray core не найден. Проверка невозможна.")
        log("        Установите бинарник в ./bin/xray или в PATH.")
        return 1
    log(f"[INFO] Используем xray: {core_path}")

    all_results = []
    batch_size = max(1, int(CFG["batch_size"]))
    total_batches = (len(parsed) + batch_size - 1) // batch_size
    port_cursor = CFG["start_port"]
    for b_idx in range(total_batches):
        batch = parsed[b_idx * batch_size:(b_idx + 1) * batch_size]
        log(f"[BATCH {b_idx + 1}/{total_batches}] size={len(batch)} port_start={port_cursor}")
        try:
            res = test_batch(core_path, batch, port_cursor)
            all_results.extend(res)
        except Exception as e:
            log(f"[WARN] Батч {b_idx + 1} упал: {e}")
        port_cursor += len(batch) + 10

    if not all_results:
        log("[RESULT] Нет рабочих VLESS конфигураций.")
        try:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write("")
        except Exception:
            pass
        return 0

    if CFG["sort_by"] == "speed":
        all_results.sort(key=lambda x: (-x[2], x[1]))
    else:
        all_results.sort(key=lambda x: (x[1], -x[2]))

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for url, _, _ in all_results:
                f.write(url + "\n")
        log("=" * 60)
        log(f"[DONE] Рабочих конфигов: {len(all_results)}. Сохранено в {OUTPUT_FILE}")
        log("=" * 60)
    except Exception as e:
        log(f"[ERROR] Не удалось записать {OUTPUT_FILE}: {e}")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\n[INTERRUPT] Прерывание пользователем.")
        sys.exit(130)
    except Exception as e:
        log(f"[FATAL] Непойманная ошибка: {e}")
        sys.exit(1)
