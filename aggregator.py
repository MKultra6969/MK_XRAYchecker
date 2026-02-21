# The original version was taken from https://github.com/y9felix/s

__version__ = "0.10.0"

import urllib.request
import concurrent.futures
import json
import os
import re
import requests
import time
import ipaddress
from urllib.parse import unquote, urlsplit
from rich.progress import track

COUNTRY_CODE_ALIASES = {
    "UK": "GB",
}

# Небольшой словарь популярных алиасов для фильтрации по странам без GeoIP.
COUNTRY_NAME_ALIASES = {
    "RUSSIA": "RU",
    "RUSSIANFEDERATION": "RU",
    "GERMANY": "DE",
    "DEUTSCHLAND": "DE",
    "UNITEDKINGDOM": "GB",
    "GREATBRITAIN": "GB",
    "BRITAIN": "GB",
    "ENGLAND": "GB",
    "USA": "US",
    "UNITEDSTATES": "US",
    "AMERICA": "US",
}

FLAG_PATTERN = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")

def _normalize_country_code(code):
    c = (code or "").strip().upper()
    if not c:
        return ""
    c = COUNTRY_CODE_ALIASES.get(c, c)
    if len(c) == 2 and c.isalpha():
        return c
    return ""

def _normalize_country_filters(country_filters):
    if not country_filters:
        return set()
    normalized = set()
    for raw in country_filters:
        token = str(raw or "").strip().upper()
        if not token:
            continue
        parts = re.split(r"[\s,;|/]+", token)
        for part in parts:
            if not part:
                continue
            cleaned = re.sub(r"[^A-Z]", "", part)
            if not cleaned:
                continue
            if len(cleaned) == 2:
                code = _normalize_country_code(cleaned)
                if code:
                    normalized.add(code)
                continue
            mapped = COUNTRY_NAME_ALIASES.get(cleaned, "")
            if mapped:
                normalized.add(mapped)
    return normalized

def _flag_to_code(flag):
    try:
        code = ''.join(chr(ord(ch) - 127397) for ch in flag)
    except Exception:
        return ""
    return _normalize_country_code(code)

def _extract_country_codes_from_hint(text):
    if not text:
        return set()
    decoded = unquote(str(text))
    upper_text = decoded.upper()
    codes = set()

    for flag in FLAG_PATTERN.findall(decoded):
        code = _flag_to_code(flag)
        if code:
            codes.add(code)

    tokens = re.split(r"[^A-Z]+", upper_text)
    for token in tokens:
        if len(token) == 2:
            code = _normalize_country_code(token)
            if code:
                codes.add(code)

    compact = re.sub(r"[^A-Z]", "", upper_text)
    for alias_name, alias_code in COUNTRY_NAME_ALIASES.items():
        if alias_name in compact:
            codes.add(alias_code)

    return codes

def _extract_hint_text(raw_line):
    if not raw_line:
        return ""
    if '#' in raw_line:
        return raw_line.split('#', 1)[1].strip()
    return ""

def _extract_host(proxy_line, host_pattern):
    match = host_pattern.search(proxy_line or "")
    if match:
        return match.group(1)
    try:
        parsed = urlsplit(proxy_line or "")
        if parsed.hostname:
            return parsed.hostname
    except Exception:
        pass
    return ""

def _is_ip_address(value):
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def fetch_single_url(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.read().decode(errors='ignore').splitlines()
    except Exception:
        return []

def get_flag(code):
    return ''.join(chr(ord(c) + 127397) for c in code.upper()) if code else ''

def get_country_batch(ip_list):
    url = "http://ip-api.com/batch?fields=countryCode,query"
    try:
        data = json.dumps(ip_list)
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=data, headers=headers, timeout=10)
        if response.status_code == 200:
            results = response.json()
            return {item['query']: item.get('countryCode', '') for item in results}
    except Exception as e:
        print(f"Ошибка GeoIP API: {e}")
    return {}

def get_aggregated_links(url_map, selected_categories, keywords, use_old=False, country_filters=None, log_func=print, console=None):
    urls = []
    old_lines = set()
    unique_configs = set()
    config_meta = {}
    
    PROTOCOL_PATTERN = re.compile(r'^(vless|vmess|trojan|ss|hysteria2|hy2)://', re.IGNORECASE)
    IP_EXTRACT_PATTERN = re.compile(r'@([^:]+):')
    wanted_countries = _normalize_country_filters(country_filters)

    if use_old and os.path.exists('old.json'):
        try:
            with open('old.json', 'r') as f:
                old_lines = set(json.load(f))
        except: pass

    for cat in selected_categories:
        sources = url_map.get(cat, [])
        if isinstance(sources, list):
            urls.extend(sources)
        elif isinstance(sources, str):
            urls.extend(sources.split())

    if console:
        console.print(f"[bold cyan]АГРЕГАТОР:[/] Загрузка из {len(urls)} источников...")
    else:
        log_func(f"АГРЕГАТОР: Загрузка из {len(urls)} источников...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = list(executor.map(fetch_single_url, urls))
        
        iterator = track(futures, description="[green]Скачивание источников...", console=console) if console else futures
        
        for result in iterator:
            for line in result:
                raw_line = line.strip()
                cleaned = raw_line.split('#')[0].strip()
                if not cleaned: continue
                if not PROTOCOL_PATTERN.match(cleaned): continue
                is_valid = True
                if keywords:
                    is_valid = any(word.lower() in line.lower() for word in keywords)
                if is_valid and cleaned not in old_lines:
                    unique_configs.add(cleaned)
                    meta = config_meta.setdefault(cleaned, {"hints": set(), "host": ""})
                    hint_text = _extract_hint_text(raw_line)
                    if hint_text:
                        meta["hints"].add(hint_text)
                    if not meta["host"]:
                        meta["host"] = _extract_host(cleaned, IP_EXTRACT_PATTERN)

    config_list = list(unique_configs)
    total_configs = len(config_list)

    if total_configs > 0:
        if wanted_countries:
            filter_codes = " ".join(sorted(wanted_countries))
            if console:
                console.print(f"[bold cyan]АГРЕГАТОР:[/] Фильтр стран: {filter_codes}")
            else:
                log_func(f"АГРЕГАТОР: Фильтр стран: {filter_codes}")

        if console:
            console.print(f"[bold cyan]АГРЕГАТОР:[/] Найдено {total_configs} конфигов. Определение стран...")
        else:
            log_func(f"АГРЕГАТОР: Найдено {total_configs} конфигов. Определение стран...")
        
        line_ip_map = {}
        selected_from_hints = []
        lookup_candidates = []

        for line in config_list:
            meta = config_meta.get(line, {})
            host = meta.get("host", "")
            line_ip_map[line] = host if _is_ip_address(host) else ""

            if wanted_countries:
                hint_codes = set()
                for hint in meta.get("hints", set()):
                    hint_codes.update(_extract_country_codes_from_hint(hint))
                matched_codes = sorted(hint_codes & wanted_countries)
                if matched_codes:
                    selected_from_hints.append((line, matched_codes[0]))
                    continue

            if line_ip_map[line]:
                lookup_candidates.append((line, line_ip_map[line]))

        ips_to_resolve = sorted({ip for _, ip in lookup_candidates})
        ip_country_map = {}
        batch_size = 100
        
        batches = range(0, len(ips_to_resolve), batch_size)
        if console:
            batches = track(batches, description="[yellow]GeoIP Resolve...", console=console)

        consecutive_errors = 0
        for i in batches:
            if consecutive_errors >= 5:
                msg = "[yellow]GeoIP API недоступен (слишком много запросов). Пропуск остальных IP...[/]"
                if console: console.print(msg)
                else: log_func(msg)
                break

            batch_ips = ips_to_resolve[i:i + batch_size]
            batch_results = get_country_batch(batch_ips)
            
            if batch_results:
                ip_country_map.update(batch_results)
                consecutive_errors = 0
                time.sleep(1.3)
            else:
                consecutive_errors += 1
                time.sleep(3)
            
        final_lines = []
        if wanted_countries:
            selected_set = set()

            for line, country_code in selected_from_hints:
                if line in selected_set:
                    continue
                selected_set.add(line)
                flag = get_flag(country_code)
                final_lines.append(f"{line}#{flag}" if flag else line)

            for line, ip in lookup_candidates:
                if line in selected_set:
                    continue
                country_code = _normalize_country_code(ip_country_map.get(ip, ''))
                if country_code and country_code in wanted_countries:
                    selected_set.add(line)
                    flag = get_flag(country_code)
                    final_lines.append(f"{line}#{flag}" if flag else line)
        else:
            for line in config_list:
                ip = line_ip_map.get(line, '')
                country_code = _normalize_country_code(ip_country_map.get(ip, '')) if ip else ''
                flag = get_flag(country_code)
                if flag:
                    final_lines.append(f"{line}#{flag}")
                else:
                    final_lines.append(line)
                
        msg = f"АГРЕГАТОР: Собрано {len(final_lines)} новых уникальных конфигураций."
        if console: console.print(f"[bold green]{msg}[/]")
        else: log_func(msg)
        
        return final_lines

    if console: console.print("[red]АГРЕГАТОР: Ничего нового не найдено.[/]")
    else: log_func("АГРЕГАТОР: Ничего нового не найдено.")
    return []

# +═════════════════════════════════════════════════════════════════════════+
# ║      ███▄ ▄███▓ ██ ▄█▀ █    ██  ██▓    ▄▄▄█████▓ ██▀███   ▄▄▄           ║
# ║     ▓██▒▀█▀ ██▒ ██▄█▒  ██  ▓██▒▓██▒    ▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄         ║
# ║     ▓██    ▓██░▓███▄░ ▓██  ▒██░▒██░    ▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄       ║
# ║     ▒██    ▒██ ▓██ █▄ ▓▓█  ░██░▒██░    ░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██      ║
# ║     ▒██▒   ░██▒▒██▒ █▄▒▒█████▓ ░██████▒  ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒     ║
# ║     ░ ▒░   ░  ░▒ ▒▒ ▓▒░▒▓▒ ▒ ▒ ░ ▒░▓  ░  ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░     ║
# ║     ░  ░      ░░ ░▒ ▒░░░▒░ ░ ░ ░ ░ ▒  ░    ░      ░▒ ░ ▒░  ▒   ▒▒ ░     ║
# ║     ░      ░   ░ ░░ ░  ░░░ ░ ░   ░ ░     ░        ░░   ░   ░   ▒        ║
# ║            ░   ░  ░      ░         ░  ░            ░           ░  ░     ║
# ║                                                                         ║
# +═════════════════════════════════════════════════════════════════════════+
# ║                               by MKultra69                              ║
# +═════════════════════════════════════════════════════════════════════════+
# +═════════════════════════════════════════════════════════════════════════+
# ║                      https://github.com/MKultra6969                     ║
# +═════════════════════════════════════════════════════════════════════════+
# +═════════════════════════════════════════════════════════════════════════+
# ║                                  mk69.su                                ║
# +═════════════════════════════════════════════════════════════════════════+
