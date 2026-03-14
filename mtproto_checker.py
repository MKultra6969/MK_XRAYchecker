# +═════════════════════════════════════════════════════════════════════════+
# ║                     MTProto checker module                              ║
# ║          Модуль для проверки прокси MTProto                             ║
# +═════════════════════════════════════════════════════════════════════════+
# ║                               by MKultra69                              ║
# +═════════════════════════════════════════════════════════════════════════+

import asyncio
import html
import logging
import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

__version__ = "1.3.0"

try:
    from telethon import TelegramClient, connection, functions, utils
    from telethon.client.telegrambaseclient import DEFAULT_DC_ID, DEFAULT_IPV4_IP, DEFAULT_IPV6_IP, DEFAULT_PORT
    from telethon.tl.alltlobjects import LAYER

    TELETHON_AVAILABLE = True
    TELETHON_IMPORT_ERROR = ""
except Exception as exc:
    TelegramClient = None
    connection = None
    functions = None
    utils = None
    DEFAULT_DC_ID = None
    DEFAULT_IPV4_IP = None
    DEFAULT_IPV6_IP = None
    DEFAULT_PORT = None
    LAYER = None
    TELETHON_AVAILABLE = False
    TELETHON_IMPORT_ERROR = str(exc)

try:
    from mtproto_faketls import ConnectionTcpMTProxyFakeTLS

    FAKETLS_AVAILABLE = True
    FAKETLS_IMPORT_ERROR = ""
except Exception as exc:
    ConnectionTcpMTProxyFakeTLS = None
    FAKETLS_AVAILABLE = False
    FAKETLS_IMPORT_ERROR = str(exc)


MTPROTO_URL_PATTERN = re.compile(
    r'(?:tg://proxy\?[^\s"\'<>]+|https?://t\.me/proxy\?[^\s"\'<>]+|t\.me/proxy\?[^\s"\'<>]+)',
    re.IGNORECASE
)
HEX_SECRET_RE = re.compile(r"^[0-9a-fA-F]+$")
STANDARD_SECRET_HEX_LEN = 32
DD_SECRET_HEX_LEN = 34
QUIET_TELETHON_LOGGER_NAME = "mk_xraychecker.mtproto.telethon"
DEFAULT_DC_PROBE_LIMIT = 3
TELEGRAM_DC_OPTIONS = [
    {"dc_id": 4, "host": "149.154.167.91", "port": 443},
    {"dc_id": 2, "host": "149.154.167.51", "port": 443},
    {"dc_id": 1, "host": "149.154.175.53", "port": 443},
    {"dc_id": 3, "host": "149.154.175.100", "port": 443},
    {"dc_id": 5, "host": "149.154.171.5", "port": 443},
]


def _setup_telethon_logging():
    for logger_name in (
        "telethon",
        "telethon.network",
        "telethon.client",
        QUIET_TELETHON_LOGGER_NAME,
    ):
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.CRITICAL)
        logger.propagate = False
        logger.disabled = True
        logger.handlers.clear()
        if not logger.handlers:
            logger.addHandler(logging.NullHandler())


_setup_telethon_logging()


def _get_quiet_telethon_logger():
    logger = logging.getLogger(QUIET_TELETHON_LOGGER_NAME)
    logger.setLevel(logging.CRITICAL)
    logger.propagate = False
    logger.disabled = True
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    return logger


def clean_mtproto_url(url):
    value = (url or "").strip()
    value = value.replace("\ufeff", "").replace("\u200b", "")
    value = value.replace("\r", "").replace("\n", "")
    value = html.unescape(value)
    value = urllib.parse.unquote(value)
    value = html.unescape(value)
    value = urllib.parse.unquote(value)
    return value.rstrip(';,)]}>')


def is_mtproto_link(value):
    cleaned = clean_mtproto_url(value).lower()
    return (
        cleaned.startswith("tg://proxy?")
        or cleaned.startswith("https://t.me/proxy?")
        or cleaned.startswith("http://t.me/proxy?")
        or cleaned.startswith("t.me/proxy?")
    )


def extract_mtproto_links(text):
    if not text:
        return [], 0

    raw_hits = 0
    unique_links = []
    seen = set()

    for match in MTPROTO_URL_PATTERN.findall(text):
        raw_hits += 1
        cleaned = clean_mtproto_url(match)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_links.append(cleaned)

    return unique_links, raw_hits


def _first_param(params, key):
    values = params.get(key, [])
    if not values:
        return ""
    return str(values[0]).strip()


def _normalize_mtproto_input(url):
    cleaned = clean_mtproto_url(url)
    lowered = cleaned.lower()
    if lowered.startswith("t.me/proxy?"):
        return "https://" + cleaned
    return cleaned


def parse_mtproto_url(raw_url):
    original_url = clean_mtproto_url(raw_url)
    if not original_url:
        return None, "Empty MTProto URL"

    normalized_url = _normalize_mtproto_input(original_url)
    parsed = urllib.parse.urlparse(normalized_url)
    scheme = parsed.scheme.lower()
    host = parsed.netloc.lower()
    path = (parsed.path or "").lower()

    if scheme == "tg":
        if host != "proxy":
            return None, "Unsupported tg:// target"
    elif scheme in ("http", "https"):
        if host != "t.me" or path != "/proxy":
            return None, "Unsupported MTProto URL host/path"
    else:
        return None, "Unsupported MTProto URL scheme"

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    server = _first_param(params, "server")
    port_raw = _first_param(params, "port")
    secret = _first_param(params, "secret")

    if not server:
        return None, "Missing server"
    if not port_raw:
        return None, "Missing port"
    if not secret:
        return None, "Missing secret"

    try:
        port = int(port_raw)
    except Exception:
        return None, "Invalid port"

    if port < 1 or port > 65535:
        return None, "Port out of range"

    secret = secret.strip()
    if not HEX_SECRET_RE.fullmatch(secret):
        return None, "Secret must be hex"

    secret_lower = secret.lower()
    secret_mode = ""
    telethon_secret = secret_lower
    if len(secret_lower) == STANDARD_SECRET_HEX_LEN:
        secret_mode = "standard"
        if secret_lower.startswith(("dd", "ee")):
            # Telethon strips lowercase dd/ee prefixes unconditionally.
            # Uppercasing preserves a normal 16-byte hex secret as-is.
            telethon_secret = secret.upper()
    elif len(secret_lower) == DD_SECRET_HEX_LEN and secret_lower.startswith("dd"):
        secret_mode = "dd"
        telethon_secret = secret.upper()
    elif len(secret_lower) > DD_SECRET_HEX_LEN and secret_lower.startswith("ee"):
        secret_mode = "ee"
        telethon_secret = secret_lower[2:]
    else:
        return None, "Unsupported secret format"

    unique_key = f"{server.lower()}:{port}:{secret_lower}"
    return {
        "original_url": original_url,
        "normalized_url": normalized_url,
        "server": server,
        "port": port,
        "secret": secret_lower,
        "secret_mode": secret_mode,
        "telethon_secret": telethon_secret,
        "unique_key": unique_key,
        "label": f"{server}:{port}",
    }, None


def parse_mtproto_content(text):
    raw_links, raw_hits = extract_mtproto_links(text)
    unique_entries = {}
    invalid_count = 0

    for item in raw_links:
        parsed, error = parse_mtproto_url(item)
        if not parsed:
            invalid_count += 1
            continue
        if parsed["unique_key"] not in unique_entries:
            unique_entries[parsed["unique_key"]] = parsed

    return list(unique_entries.values()), raw_hits, invalid_count


def fetch_mtproto_entries(url, timeout=15, log_func=None):
    if log_func:
        log_func(f"[cyan]>> Загрузка MTProto URL: {url}[/]")

    response = requests.get(url, timeout=timeout, verify=False)
    response.raise_for_status()
    entries, raw_hits, invalid_count = parse_mtproto_content(response.text)
    return entries, raw_hits, invalid_count


def validate_runtime_config(runtime_cfg):
    if not isinstance(runtime_cfg, dict):
        return False, "MTProto config must be a dict"

    if not TELETHON_AVAILABLE:
        return False, (
            "Telethon не установлен"
            + (f": {TELETHON_IMPORT_ERROR}" if TELETHON_IMPORT_ERROR else "")
        )

    try:
        api_id = int(runtime_cfg.get("api_id") or 0)
    except Exception:
        api_id = 0

    api_hash = str(runtime_cfg.get("api_hash") or "").strip()
    if api_id <= 0:
        return False, "MTProto api_id не задан в config.json"
    if not api_hash:
        return False, "MTProto api_hash не задан в config.json"
    return True, None


def rank_telegram_dcs(timeout=1.5, limit=DEFAULT_DC_PROBE_LIMIT):
    ranked = []
    fallback = []
    for dc in TELEGRAM_DC_OPTIONS:
        dc_copy = dict(dc)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        started = time.perf_counter()
        try:
            sock.connect((dc["host"], dc["port"]))
            dc_copy["probe_ms"] = round((time.perf_counter() - started) * 1000)
            ranked.append(dc_copy)
        except Exception:
            dc_copy["probe_ms"] = None
            fallback.append(dc_copy)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    ranked.sort(key=lambda item: item.get("probe_ms", 10**9))
    ordered = ranked + fallback
    if limit and limit > 0:
        return ordered[:limit]
    return ordered


def _format_probe_error(exc):
    message = str(exc).strip()
    if not message:
        return exc.__class__.__name__
    return f"{exc.__class__.__name__}: {message}"


def _build_connection_candidates(entry):
    secret_mode = entry.get("secret_mode")
    if secret_mode == "ee":
        return [("faketls", ConnectionTcpMTProxyFakeTLS)] if FAKETLS_AVAILABLE and ConnectionTcpMTProxyFakeTLS else []
    if secret_mode == "dd":
        return [
            ("randomized", connection.ConnectionTcpMTProxyRandomizedIntermediate),
            ("intermediate", connection.ConnectionTcpMTProxyIntermediate),
            ("abridged", connection.ConnectionTcpMTProxyAbridged),
        ]
    return [
        ("intermediate", connection.ConnectionTcpMTProxyIntermediate),
        ("abridged", connection.ConnectionTcpMTProxyAbridged),
        ("randomized", connection.ConnectionTcpMTProxyRandomizedIntermediate),
    ]


async def _connect_sender_only(client, timeout, dc_candidate=None):
    if dc_candidate:
        await utils.maybe_async(
            client.session.set_dc(
                int(dc_candidate["dc_id"]),
                str(dc_candidate["host"]),
                int(dc_candidate["port"]),
            )
        )
        await utils.maybe_async(client.session.save())
    elif (not client.session.server_address) or (":" in client.session.server_address) != client._use_ipv6:
        await utils.maybe_async(
            client.session.set_dc(
                DEFAULT_DC_ID,
                DEFAULT_IPV6_IP if client._use_ipv6 else DEFAULT_IPV4_IP,
                DEFAULT_PORT,
            )
        )
        await utils.maybe_async(client.session.save())

    connection_instance = client._connection(
        client.session.server_address,
        client.session.port,
        client.session.dc_id,
        loggers=client._log,
        proxy=client._proxy,
        local_addr=client._local_addr,
    )
    await asyncio.wait_for(client._sender.connect(connection_instance), timeout=timeout)
    client.session.auth_key = client._sender.auth_key
    await utils.maybe_async(client.session.save())


async def _invoke_probe_request(client, timeout):
    client.session.auth_key = client._sender.auth_key
    await utils.maybe_async(client.session.save())

    client._init_request.query = functions.help.GetConfigRequest()
    request = client._init_request
    if client._no_updates:
        request = functions.InvokeWithoutUpdatesRequest(request)

    return await asyncio.wait_for(
        client._sender.send(functions.InvokeWithLayerRequest(LAYER, request)),
        timeout=timeout,
    )


async def _probe_mtproto_async(entry, runtime_cfg):
    api_id = int(runtime_cfg.get("api_id") or 0)
    api_hash = str(runtime_cfg.get("api_hash") or "").strip()
    timeout = float(runtime_cfg.get("timeout") or 5)

    candidates = _build_connection_candidates(entry)
    if not candidates:
        return {
            "entry": entry,
            "ping_ms": None,
            "status": "fail",
            "error": (
                "FakeTLS backend unavailable"
                + (f": {FAKETLS_IMPORT_ERROR}" if FAKETLS_IMPORT_ERROR else "")
            ),
        }

    dc_candidates = runtime_cfg.get("dc_candidates") or TELEGRAM_DC_OPTIONS[:DEFAULT_DC_PROBE_LIMIT]
    best_connect_only = None
    last_error = "Unknown error"
    for dc_candidate in dc_candidates:
        dc_id = dc_candidate.get("dc_id")
        for transport_name, connection_cls in candidates:
            client = TelegramClient(
                None,
                api_id,
                api_hash,
                connection=connection_cls,
                proxy=(entry["server"], entry["port"], entry.get("telethon_secret", entry["secret"])),
                timeout=timeout,
                request_retries=0,
                connection_retries=0,
                retry_delay=0,
                auto_reconnect=False,
                receive_updates=False,
                sequential_updates=False,
                device_model="MK_XRAYchecker",
                app_version="mtproto-checker",
                system_version="python",
                lang_code="en",
                system_lang_code="en",
                base_logger=_get_quiet_telethon_logger(),
            )

            start_time = time.perf_counter()
            try:
                await _connect_sender_only(client, timeout, dc_candidate=dc_candidate)
                connect_ping_ms = round((time.perf_counter() - start_time) * 1000)
                if not client.is_connected():
                    last_error = f"dc{dc_id}/{transport_name}: Disconnected after connect"
                    continue

                try:
                    await _invoke_probe_request(client, timeout)
                    return {
                        "entry": entry,
                        "ping_ms": connect_ping_ms,
                        "status": "live",
                        "error": None,
                        "transport": transport_name,
                        "dc_id": dc_id,
                    }
                except Exception as exc:
                    best_connect_only = {
                        "entry": entry,
                        "ping_ms": connect_ping_ms,
                        "status": "connect_only",
                        "error": _format_probe_error(exc),
                        "transport": transport_name,
                        "dc_id": dc_id,
                    }
                    last_error = f"dc{dc_id}/{transport_name}: {best_connect_only['error']}"
            except asyncio.TimeoutError:
                last_error = f"dc{dc_id}/{transport_name}: Timeout"
            except Exception as exc:
                last_error = f"dc{dc_id}/{transport_name}: {_format_probe_error(exc)}"
            finally:
                try:
                    await client.disconnect()
                    await asyncio.sleep(0)
                except Exception:
                    pass

    if best_connect_only is not None:
        return best_connect_only

    return {
        "entry": entry,
        "ping_ms": None,
        "status": "fail",
        "error": last_error,
    }


def _probe_mtproto_sync(entry, runtime_cfg):
    loop = asyncio.new_event_loop()

    def _exception_handler(current_loop, context):
        message = str(context.get("message") or "")
        exc = context.get("exception")
        if "Future exception was never retrieved" in message and isinstance(
            exc,
            (
                asyncio.IncompleteReadError,
                ConnectionError,
                TimeoutError,
                OSError,
            ),
        ):
            return
        current_loop.default_exception_handler(context)

    loop.set_exception_handler(_exception_handler)
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(_probe_mtproto_async(entry, runtime_cfg))
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        asyncio.set_event_loop(None)
        loop.close()


def run_mtproto_check(entries, runtime_cfg, log_func=None, progress_callback=None):
    ok, error = validate_runtime_config(runtime_cfg)
    if not ok:
        raise RuntimeError(error)

    max_ping_ms = int(runtime_cfg.get("max_ping_ms") or 0)
    threads = int(runtime_cfg.get("threads") or 1)
    if threads < 1:
        threads = 1

    current_live_results = []
    all_results = []
    if not entries:
        return current_live_results, all_results

    max_workers = min(len(entries), threads)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_probe_mtproto_sync, entry, runtime_cfg) for entry in entries]

        for future in as_completed(futures):
            result = future.result()
            all_results.append(result)

            entry = result["entry"]
            label = entry["label"]
            ping_ms = result["ping_ms"]
            error_reason = result["error"]

            if ping_ms is not None:
                if result.get("status") == "connect_only":
                    if log_func:
                        log_func(
                            f"[cyan][CONN][/] [white]{label:<25}[/] | "
                            f"{ping_ms:>4}ms | {error_reason or 'RPC failed'} | mtproto"
                        )
                elif max_ping_ms and ping_ms > max_ping_ms:
                    result["status"] = "drop"
                    if log_func:
                        log_func(
                            f"[yellow][DROP][/] [white]{label:<25}[/] | "
                            f"{ping_ms:>4}ms > {max_ping_ms}ms | mtproto"
                        )
                else:
                    result["status"] = "live"
                    if log_func:
                        log_func(
                            f"[green][LIVE][/] [white]{label:<25}[/] | "
                            f"{ping_ms:>4}ms | mtproto"
                        )
                    current_live_results.append((entry["original_url"], ping_ms, 0.0))
            else:
                result["status"] = "fail"
                if log_func:
                    log_func(
                        f"[red][FAIL][/] [white]{label:<25}[/] | "
                        f"{error_reason or 'Unknown error'} | mtproto"
                    )

            if progress_callback:
                progress_callback()

    return current_live_results, all_results


def run_parser_self_test(log_func=print):
    test_cases = [
        (
            "tg://proxy?server=1.2.3.4&port=443&secret=0123456789abcdef0123456789abcdef",
            True,
        ),
        (
            "https://t.me/proxy?server=example.com&port=8443&secret=dd0123456789abcdef0123456789abcdef",
            True,
        ),
        (
            "tg://proxy?server=example.com&port=443&secret=dd0123456789abcdef0123456789abcd",
            True,
        ),
        (
            "tg://proxy?server=example.com&port=443&secret=ee9b43b87555bf9464e02bdcd2db8932b07777772e736974652e636f6d",
            True,
        ),
        (
            "https://t.me/proxy?server=example.com&port=443",
            False,
        ),
    ]

    passed = 0
    for raw_url, should_pass in test_cases:
        parsed, _ = parse_mtproto_url(raw_url)
        is_ok = parsed is not None
        if is_ok == should_pass:
            passed += 1
            log_func(f"[green]MTProto PASS[/]: {raw_url[:80]}")
        else:
            log_func(f"[red]MTProto FAIL[/]: {raw_url[:80]}")

    total = len(test_cases)
    log_func(f"[bold]MTProto self-test: {passed}/{total} passed[/]")
    return passed == total
