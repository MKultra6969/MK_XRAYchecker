# +═════════════════════════════════════════════════════════════════════════+
# ║                     MTProto checker module                              ║
# ║          Модуль для проверки прокси MTProto                             ║
# +═════════════════════════════════════════════════════════════════════════+
# ║                               by MKultra69                              ║
# +═════════════════════════════════════════════════════════════════════════+

import asyncio
import base64
import binascii
import html
import logging
import os
import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

__version__ = "1.4.1"
ALLOWED_CRYPTO_BACKENDS = {"auto", "safe", "unsafe"}

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
    from mtproto_faketls import (
        ConnectionTcpMTProxyFakeTLS,
        ConnectionTcpMTProxyFakeTLSAbridged,
        ConnectionTcpMTProxyFakeTLSIntermediate,
    )

    FAKETLS_AVAILABLE = True
    FAKETLS_IMPORT_ERROR = ""
except Exception as exc:
    ConnectionTcpMTProxyFakeTLS = None
    ConnectionTcpMTProxyFakeTLSAbridged = None
    ConnectionTcpMTProxyFakeTLSIntermediate = None
    FAKETLS_AVAILABLE = False
    FAKETLS_IMPORT_ERROR = str(exc)


MTPROTO_URL_PATTERN = re.compile(
    r'(?:tg://proxy\?[^\s"\'<>]+|https?://t\.me/proxy\?[^\s"\'<>]+|t\.me/proxy\?[^\s"\'<>]+)',
    re.IGNORECASE
)
TELEGRAM_PROXY_LIKE_URL_PATTERN = re.compile(
    r'(?:tg://(?:proxy|socks)\?[^\s"\'<>]+|https?://t\.me/(?:proxy|socks)\?[^\s"\'<>]+|t\.me/(?:proxy|socks)\?[^\s"\'<>]+)',
    re.IGNORECASE
)
HEX_SECRET_RE = re.compile(r"^[0-9a-fA-F]+$")
BASE64_SECRET_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
BASE64_URLSAFE_SECRET_RE = re.compile(r"^[A-Za-z0-9\-_]*={0,2}$")
STANDARD_SECRET_HEX_LEN = 32
DD_SECRET_HEX_LEN = 34
QUIET_TELETHON_LOGGER_NAME = "mk_xraychecker.mtproto.telethon"
DEFAULT_DC_PROBE_LIMIT = 3
SAFE_CRYPTO_ENV_VAR = "MK_MTPROTO_ALLOW_UNSAFE_CRYPTG"
TELEGRAM_DC_OPTIONS = [
    {"dc_id": 4, "host": "149.154.167.91", "port": 443},
    {"dc_id": 2, "host": "149.154.167.51", "port": 443},
    {"dc_id": 1, "host": "149.154.175.53", "port": 443},
    {"dc_id": 3, "host": "149.154.175.100", "port": 443},
    {"dc_id": 5, "host": "149.154.171.5", "port": 443},
]
_TELETHON_LIBSSL_ORIGINALS = None
_TELETHON_AES_DECRYPT_ORIGINAL = None
_TELETHON_AES_GUARD_INSTALLED = False


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


def _env_flag_enabled(name):
    value = str(os.environ.get(name) or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _get_telethon_aes_module():
    if not TELETHON_AVAILABLE:
        return None

    try:
        from telethon.crypto import aes as telethon_aes
    except Exception:
        return None
    return telethon_aes


def _get_telethon_libssl_module():
    telethon_aes = _get_telethon_aes_module()
    if telethon_aes is None:
        return None
    return getattr(telethon_aes, "libssl", None)


def _get_cryptg_module():
    try:
        import cryptg
    except Exception:
        return None
    return cryptg


def _store_telethon_native_crypto_state():
    global _TELETHON_LIBSSL_ORIGINALS

    telethon_libssl = _get_telethon_libssl_module()
    if telethon_libssl is None:
        return None

    if _TELETHON_LIBSSL_ORIGINALS is None:
        _TELETHON_LIBSSL_ORIGINALS = {
            "encrypt_ige": getattr(telethon_libssl, "encrypt_ige", None),
            "decrypt_ige": getattr(telethon_libssl, "decrypt_ige", None),
        }

    return telethon_libssl


def _install_telethon_aes_guard():
    global _TELETHON_AES_DECRYPT_ORIGINAL, _TELETHON_AES_GUARD_INSTALLED

    telethon_aes = _get_telethon_aes_module()
    if telethon_aes is None or _TELETHON_AES_GUARD_INSTALLED:
        return telethon_aes

    aes_cls = getattr(telethon_aes, "AES", None)
    if aes_cls is None:
        return telethon_aes

    _TELETHON_AES_DECRYPT_ORIGINAL = aes_cls.decrypt_ige

    def _guarded_decrypt_ige(cipher_text, key, iv):
        cipher_text = bytes(cipher_text)
        if len(cipher_text) % 16 != 0:
            raise ValueError(
                f"MTProto ciphertext length must be divisible by 16 (got {len(cipher_text)})"
            )
        return _TELETHON_AES_DECRYPT_ORIGINAL(cipher_text, key, iv)

    aes_cls.decrypt_ige = staticmethod(_guarded_decrypt_ige)
    _TELETHON_AES_GUARD_INSTALLED = True
    return telethon_aes


def _configure_telethon_crypto(mode):
    telethon_aes = _install_telethon_aes_guard()
    if telethon_aes is None:
        return None

    telethon_libssl = _store_telethon_native_crypto_state()
    if mode == "unsafe":
        telethon_aes.cryptg = _get_cryptg_module()
        if telethon_libssl is not None and _TELETHON_LIBSSL_ORIGINALS is not None:
            telethon_libssl.encrypt_ige = _TELETHON_LIBSSL_ORIGINALS["encrypt_ige"]
            telethon_libssl.decrypt_ige = _TELETHON_LIBSSL_ORIGINALS["decrypt_ige"]
    else:
        telethon_aes.cryptg = None
        if telethon_libssl is not None:
            telethon_libssl.encrypt_ige = None
            telethon_libssl.decrypt_ige = None

    return telethon_aes


def _entries_need_safe_crypto(entries):
    if not entries:
        return False

    for entry in entries:
        if isinstance(entry, dict) and str(entry.get("secret_mode") or "").lower() == "ee":
            return True
    return False


def _resolve_crypto_backend(runtime_cfg, entries=None):
    requested = str((runtime_cfg or {}).get("crypto_backend", "auto") or "auto").strip().lower()
    if requested not in ALLOWED_CRYPTO_BACKENDS:
        requested = "auto"

    cryptg_available = _get_cryptg_module() is not None
    if requested == "safe":
        return {
            "requested": requested,
            "effective": "safe",
            "cryptg_available": cryptg_available,
            "reason": "forced safe mode",
        }

    if requested == "unsafe":
        if cryptg_available:
            return {
                "requested": requested,
                "effective": "unsafe",
                "cryptg_available": True,
                "reason": "forced unsafe mode",
            }
        return {
            "requested": requested,
            "effective": "safe",
            "cryptg_available": False,
            "reason": "forced unsafe mode requested, but cryptg is unavailable",
        }

    if _env_flag_enabled(SAFE_CRYPTO_ENV_VAR):
        if cryptg_available:
            return {
                "requested": requested,
                "effective": "unsafe",
                "cryptg_available": True,
                "reason": f"legacy env override {SAFE_CRYPTO_ENV_VAR}=1",
            }
        return {
            "requested": requested,
            "effective": "safe",
            "cryptg_available": False,
            "reason": f"legacy env override requested unsafe, but cryptg is unavailable",
        }

    if not cryptg_available:
        return {
            "requested": requested,
            "effective": "safe",
            "cryptg_available": False,
            "reason": "cryptg not installed",
        }

    if _entries_need_safe_crypto(entries):
        return {
            "requested": requested,
            "effective": "safe",
            "cryptg_available": True,
            "reason": "FakeTLS entries detected",
        }

    if os.name != "nt":
        return {
            "requested": requested,
            "effective": "safe",
            "cryptg_available": True,
            "reason": f"conservative auto mode on {os.name}",
        }

    return {
        "requested": requested,
        "effective": "unsafe",
        "cryptg_available": True,
        "reason": "cryptg available on Windows without FakeTLS entries",
    }


def describe_crypto_backend(runtime_cfg, entries=None):
    resolved = _resolve_crypto_backend(runtime_cfg, entries=entries)
    requested = resolved["requested"]
    effective = resolved["effective"]
    reason = resolved["reason"]
    if requested == effective:
        return f"{effective} ({reason})"
    return f"{requested} -> {effective} ({reason})"


def configure_runtime_crypto_backend(runtime_cfg, entries=None):
    resolved = _resolve_crypto_backend(runtime_cfg, entries=entries)
    _configure_telethon_crypto(resolved["effective"])
    return resolved


def _configure_safe_telethon_crypto():
    if not TELETHON_AVAILABLE:
        return

    if _env_flag_enabled(SAFE_CRYPTO_ENV_VAR):
        return

    _configure_telethon_crypto("safe")


_configure_safe_telethon_crypto()


def clean_mtproto_url(url):
    value = (url or "").strip()
    value = value.replace("\ufeff", "").replace("\u200b", "")
    value = value.replace("\r", "").replace("\n", "")
    value = html.unescape(value)
    value = urllib.parse.unquote(value)
    value = html.unescape(value)
    value = urllib.parse.unquote(value)
    return value.rstrip(';,)]}>')


def is_telegram_proxy_link(value):
    cleaned = clean_mtproto_url(value).lower()
    return (
        cleaned.startswith("tg://proxy?")
        or cleaned.startswith("tg://socks?")
        or cleaned.startswith("https://t.me/proxy?")
        or cleaned.startswith("https://t.me/socks?")
        or cleaned.startswith("http://t.me/proxy?")
        or cleaned.startswith("http://t.me/socks?")
        or cleaned.startswith("t.me/proxy?")
        or cleaned.startswith("t.me/socks?")
    )


def is_mtproto_link(value):
    return is_telegram_proxy_link(value)


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


def extract_telegram_proxy_like_links(text):
    if not text:
        return [], 0

    raw_hits = 0
    unique_links = []
    seen = set()

    for match in TELEGRAM_PROXY_LIKE_URL_PATTERN.findall(text):
        raw_hits += 1
        cleaned = clean_mtproto_url(match)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_links.append(cleaned)

    return unique_links, raw_hits


def _first_param(params, key, *, strip=True):
    values = params.get(key, [])
    if not values:
        return ""
    value = str(values[0])
    return value.strip() if strip else value


def _decode_base64_secret(secret, *, urlsafe=False):
    raw = (secret or "").strip()
    alphabet_re = BASE64_URLSAFE_SECRET_RE if urlsafe else BASE64_SECRET_RE
    if not raw or not alphabet_re.fullmatch(raw):
        raise ValueError("Unsupported secret encoding")
    if "=" in raw[:-2]:
        raise ValueError("Invalid base64 padding")

    padless = raw.rstrip("=")
    if len(raw) - len(padless) > 2 or (len(padless) % 4) == 1:
        raise ValueError("Invalid base64 length")

    normalized = padless
    if urlsafe:
        normalized = normalized.replace("-", "+").replace("_", "/")
    padded = normalized + ("=" * (-len(normalized) % 4))
    try:
        return base64.b64decode(padded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid base64 secret") from exc


def _classify_secret_bytes(secret_bytes):
    if len(secret_bytes) == 16:
        return "standard", None
    if len(secret_bytes) == 17 and secret_bytes[0] == 0xDD:
        return "dd", None
    if len(secret_bytes) >= 18 and secret_bytes[0] == 0xEE:
        domain_bytes = secret_bytes[17:]
        if not domain_bytes:
            raise ValueError("FakeTLS secret is missing domain")
        if any(byte < 0x20 or byte == 0x7F for byte in domain_bytes):
            raise ValueError("FakeTLS domain contains control characters")
        try:
            fake_tls_domain = domain_bytes.decode("utf-8")
        except UnicodeDecodeError:
            fake_tls_domain = domain_bytes.decode("utf-8", errors="replace")
        return "ee", fake_tls_domain
    raise ValueError("Unsupported secret format")


def decode_mtproto_secret(secret_raw):
    secret_text = "" if secret_raw is None else str(secret_raw)
    if not secret_text.strip():
        raise ValueError("Missing secret")

    secret_text_hex = secret_text.strip()
    secret_text_base64 = secret_text.replace(" ", "+").strip()
    secret_bytes = None
    secret_encoding = ""

    if HEX_SECRET_RE.fullmatch(secret_text_hex):
        try:
            secret_bytes = bytes.fromhex(secret_text_hex)
        except ValueError as exc:
            raise ValueError("Invalid hex secret") from exc
        secret_encoding = "hex"
    else:
        has_std_symbols = ("+" in secret_text_base64) or ("/" in secret_text_base64)
        has_urlsafe_symbols = ("-" in secret_text_base64) or ("_" in secret_text_base64)
        if has_std_symbols and has_urlsafe_symbols:
            raise ValueError("Mixed base64 alphabets are not supported")

        candidates = []
        if has_urlsafe_symbols:
            candidates.append(("base64url", True))
        elif has_std_symbols:
            candidates.append(("base64", False))
        else:
            candidates.extend((
                ("base64", False),
                ("base64url", True),
            ))

        last_error = "Unsupported secret encoding"
        for encoding_name, urlsafe in candidates:
            try:
                secret_bytes = _decode_base64_secret(secret_text_base64, urlsafe=urlsafe)
                secret_encoding = encoding_name
                break
            except ValueError as exc:
                last_error = str(exc)

        if secret_bytes is None:
            raise ValueError(last_error)

    secret_mode, fake_tls_domain = _classify_secret_bytes(secret_bytes)
    secret_hex = secret_bytes.hex()
    if secret_mode == "ee":
        telethon_secret = secret_bytes
    elif secret_mode == "dd":
        telethon_secret = secret_hex
    else:
        telethon_secret = secret_hex.upper() if secret_hex.startswith(("dd", "ee")) else secret_hex

    return {
        "secret_raw": secret_text_hex if secret_encoding == "hex" else secret_text_base64,
        "secret_bytes": secret_bytes,
        "secret_encoding": secret_encoding,
        "secret_mode": secret_mode,
        "secret_hex": secret_hex,
        "fake_tls_domain": fake_tls_domain,
        "telethon_secret": telethon_secret,
    }


def _build_canonical_mtproto_url(server, port, secret_hex):
    query = urllib.parse.urlencode({
        "server": server,
        "port": str(port),
        "secret": secret_hex,
    })
    return f"tg://proxy?{query}"


def _build_canonical_socks_url(server, port, username=None, password=None):
    query_items = [
        ("server", server),
        ("port", str(port)),
    ]
    if username:
        query_items.append(("user", username))
    if password:
        query_items.append(("pass", password))
    return f"tg://socks?{urllib.parse.urlencode(query_items)}"


def _normalize_mtproto_input(url):
    cleaned = clean_mtproto_url(url)
    lowered = cleaned.lower()
    if lowered.startswith("t.me/proxy?") or lowered.startswith("t.me/socks?"):
        return "https://" + cleaned
    return cleaned


def parse_mtproto_url(raw_url):
    original_url = clean_mtproto_url(raw_url)
    if not original_url:
        return None, "Empty Telegram proxy URL"

    normalized_url = _normalize_mtproto_input(original_url)
    parsed = urllib.parse.urlparse(normalized_url)
    scheme = parsed.scheme.lower()
    host = parsed.netloc.lower()
    path = (parsed.path or "").lower()
    proxy_kind = None

    if scheme == "tg":
        if host == "proxy":
            proxy_kind = "mtproto"
        elif host == "socks":
            proxy_kind = "socks"
        else:
            return None, "Unsupported Telegram proxy target"
    elif scheme in ("http", "https"):
        if host != "t.me":
            return None, "Unsupported Telegram proxy URL host/path"
        if path == "/proxy":
            proxy_kind = "mtproto"
        elif path == "/socks":
            proxy_kind = "socks"
        else:
            return None, "Unsupported Telegram proxy URL host/path"
    else:
        return None, "Unsupported Telegram proxy URL scheme"

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    server = _first_param(params, "server")
    port_raw = _first_param(params, "port")

    if not server:
        return None, "Missing server"
    if not port_raw:
        return None, "Missing port"

    try:
        port = int(port_raw)
    except Exception:
        return None, "Invalid port"

    if port < 1 or port > 65535:
        return None, "Port out of range"

    if proxy_kind == "socks":
        username = _first_param(params, "user") or _first_param(params, "username")
        password = _first_param(params, "pass") or _first_param(params, "password")
        unique_key = f"socks:{server.lower()}:{port}:{username}:{password}"
        canonical_url = _build_canonical_socks_url(server, port, username, password)
        return {
            "original_url": original_url,
            "canonical_url": canonical_url,
            "normalized_url": normalized_url,
            "proxy_kind": "socks",
            "server": server,
            "port": port,
            "socks_username": username,
            "socks_password": password,
            "telethon_proxy": ("socks5", server, port, True, username or None, password or None),
            "unique_key": unique_key,
            "label": f"{server}:{port}",
        }, None

    secret = _first_param(params, "secret", strip=False)
    if not secret:
        return None, "Missing secret"

    try:
        secret_meta = decode_mtproto_secret(secret)
    except ValueError as exc:
        return None, str(exc)

    secret_hex = secret_meta["secret_hex"]
    unique_key = f"mtproto:{server.lower()}:{port}:{secret_hex}"
    canonical_url = _build_canonical_mtproto_url(server, port, secret_hex)
    return {
        "original_url": original_url,
        "canonical_url": canonical_url,
        "normalized_url": normalized_url,
        "proxy_kind": "mtproto",
        "server": server,
        "port": port,
        "secret": secret_hex,
        "secret_raw": secret_meta["secret_raw"],
        "secret_hex": secret_hex,
        "secret_bytes": secret_meta["secret_bytes"],
        "secret_encoding": secret_meta["secret_encoding"],
        "secret_mode": secret_meta["secret_mode"],
        "fake_tls_domain": secret_meta["fake_tls_domain"],
        "telethon_secret": secret_meta["telethon_secret"],
        "telethon_proxy": (server, port, secret_meta["telethon_secret"]),
        "unique_key": unique_key,
        "label": f"{server}:{port}",
    }, None


def parse_mtproto_content(text):
    proxy_like_links, proxy_like_hits = extract_telegram_proxy_like_links(text)
    unique_entries = {}
    invalid_count = 0
    mtproto_hits = 0
    socks_hits = 0

    for item in proxy_like_links:
        parsed, error = parse_mtproto_url(item)
        if not parsed:
            invalid_count += 1
            continue
        if parsed.get("proxy_kind") == "socks":
            socks_hits += 1
        else:
            mtproto_hits += 1
        if parsed["unique_key"] not in unique_entries:
            unique_entries[parsed["unique_key"]] = parsed

    return list(unique_entries.values()), mtproto_hits, socks_hits, invalid_count, proxy_like_hits


def fetch_mtproto_entries(url, timeout=15, log_func=None):
    if log_func:
        log_func(f"[cyan]>> Загрузка Telegram proxy URL: {url}[/]")

    response = requests.get(url, timeout=timeout, verify=False)
    response.raise_for_status()
    entries, mtproto_hits, socks_hits, invalid_count, proxy_like_hits = parse_mtproto_content(response.text)
    return entries, mtproto_hits, socks_hits, invalid_count, proxy_like_hits


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
    crypto_backend = str(runtime_cfg.get("crypto_backend", "auto") or "auto").strip().lower()
    if api_id <= 0:
        return False, "MTProto api_id не задан в config.json"
    if not api_hash:
        return False, "MTProto api_hash не задан в config.json"
    if crypto_backend not in ALLOWED_CRYPTO_BACKENDS:
        allowed = "/".join(sorted(ALLOWED_CRYPTO_BACKENDS))
        return False, f"MTProto crypto_backend должен быть одним из: {allowed}"
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


def _normalize_dc_candidates(candidates):
    normalized = []
    seen_dc_ids = set()
    for item in candidates or []:
        if not isinstance(item, dict):
            continue
        dc_id = item.get("dc_id")
        if dc_id in seen_dc_ids:
            continue
        normalized.append(dict(item))
        seen_dc_ids.add(dc_id)
    return normalized


def _build_dc_attempt_batches(runtime_cfg):
    preferred = _normalize_dc_candidates(
        (runtime_cfg or {}).get("dc_candidates")
        or TELEGRAM_DC_OPTIONS[:DEFAULT_DC_PROBE_LIMIT]
    )
    all_candidates = _normalize_dc_candidates(
        (runtime_cfg or {}).get("all_dc_candidates")
        or TELEGRAM_DC_OPTIONS
    )

    if not preferred:
        preferred = list(all_candidates)

    remaining = []
    seen_dc_ids = {item.get("dc_id") for item in preferred}
    for item in all_candidates:
        if item.get("dc_id") in seen_dc_ids:
            continue
        remaining.append(item)

    batches = []
    if preferred:
        batches.append(preferred)
    if remaining:
        batches.append(remaining)
    return batches


def _format_probe_error(exc):
    if isinstance(exc, ValueError) and str(exc).startswith(
        "MTProto ciphertext length must be divisible by 16"
    ):
        return "Invalid MTProto packet (ciphertext length is not aligned to AES block size)"

    message = str(exc).strip()
    if not message:
        return exc.__class__.__name__
    return f"{exc.__class__.__name__}: {message}"


def _should_reraise_base_exception(exc):
    return isinstance(exc, (KeyboardInterrupt, SystemExit))


def _build_connection_candidates(entry):
    if str(entry.get("proxy_kind") or "").lower() == "socks":
        return [("socks5", connection.ConnectionTcpFull)]

    secret_mode = entry.get("secret_mode")
    if secret_mode == "ee":
        if not FAKETLS_AVAILABLE or not ConnectionTcpMTProxyFakeTLS:
            return []
        return [
            ("faketls-abridged", ConnectionTcpMTProxyFakeTLSAbridged),
            ("faketls-intermediate", ConnectionTcpMTProxyFakeTLSIntermediate),
            ("faketls-randomized", ConnectionTcpMTProxyFakeTLS),
        ]
    if secret_mode == "dd":
        return [("randomized", connection.ConnectionTcpMTProxyRandomizedIntermediate)]
    return [
        ("intermediate", connection.ConnectionTcpMTProxyIntermediate),
        ("abridged", connection.ConnectionTcpMTProxyAbridged),
        ("randomized", connection.ConnectionTcpMTProxyRandomizedIntermediate),
    ]


def _is_expected_mtproto_future_noise(context):
    message = str((context or {}).get("message") or "")
    if "Future exception was never retrieved" not in message:
        return False

    exc = (context or {}).get("exception")
    if isinstance(exc, (asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError)):
        return True

    if isinstance(exc, ValueError) and str(exc).startswith(
        "MTProto ciphertext length must be divisible by 16"
    ):
        return True

    return False


def _is_expected_mtproto_proactor_close_noise(context):
    if os.name != "nt":
        return False

    message = str((context or {}).get("message") or "")
    handle = (context or {}).get("handle")
    callback = getattr(handle, "_callback", None)
    callback_name = str(
        getattr(callback, "__qualname__", None)
        or getattr(callback, "__name__", None)
        or ""
    )
    if (
        callback_name != "_ProactorBasePipeTransport._call_connection_lost"
        and not message.startswith("Exception in callback _ProactorBasePipeTransport._call_connection_lost")
    ):
        return False

    exc = (context or {}).get("exception")
    if not isinstance(exc, ConnectionResetError):
        return False

    winerror = getattr(exc, "winerror", None)
    if winerror is None:
        errno = getattr(exc, "errno", None)
        if errno is not None:
            winerror = errno
    if winerror is None and getattr(exc, "args", None):
        first_arg = exc.args[0]
        if isinstance(first_arg, int):
            winerror = first_arg

    return winerror == 10054


def _is_expected_mtproto_loop_noise(context):
    return _is_expected_mtproto_future_noise(context) or _is_expected_mtproto_proactor_close_noise(context)


def _get_probe_connect_timeout(entry, runtime_cfg):
    base_timeout = float((runtime_cfg or {}).get("timeout") or 5)
    if isinstance(entry, dict) and str(entry.get("secret_mode") or "").lower() == "ee":
        return max(base_timeout, 10.0)
    return base_timeout


async def _probe_proxy_reachability(entry, timeout):
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=entry["server"], port=int(entry["port"])),
            timeout=timeout,
        )
        return None
    except asyncio.TimeoutError:
        return f"Proxy TCP connect timed out after {int(timeout)}s"
    except OSError as exc:
        return f"Proxy TCP connect failed: {_format_probe_error(exc)}"
    finally:
        if writer is not None:
            try:
                writer.close()
                wait_closed = getattr(writer, "wait_closed", None)
                if callable(wait_closed):
                    await asyncio.wait_for(wait_closed(), timeout=1)
            except Exception:
                pass


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
    connect_timeout = _get_probe_connect_timeout(entry, runtime_cfg)
    proxy_reachability_timeout = min(max(timeout, 1.0), 5.0)

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

    proxy_error = await _probe_proxy_reachability(entry, proxy_reachability_timeout)
    if proxy_error:
        return {
            "entry": entry,
            "ping_ms": None,
            "status": "proxy_unreachable",
            "error": proxy_error,
        }

    dc_attempt_batches = _build_dc_attempt_batches(runtime_cfg)
    best_connect_only = None
    last_error = "Unknown error"
    for dc_candidates in dc_attempt_batches:
        for dc_candidate in dc_candidates:
            dc_id = dc_candidate.get("dc_id")
            for transport_name, connection_cls in candidates:
                client = None
                start_time = time.perf_counter()
                try:
                    client = TelegramClient(
                        None,
                        api_id,
                        api_hash,
                        connection=connection_cls,
                        proxy=entry.get("telethon_proxy", (entry["server"], entry["port"], entry.get("telethon_secret", entry.get("secret")))),
                        timeout=connect_timeout,
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
                    await _connect_sender_only(client, connect_timeout, dc_candidate=dc_candidate)
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
                    except BaseException as exc:
                        if _should_reraise_base_exception(exc):
                            raise
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
                except BaseException as exc:
                    if _should_reraise_base_exception(exc):
                        raise
                    last_error = f"dc{dc_id}/{transport_name}: {_format_probe_error(exc)}"
                finally:
                    if client is not None:
                        try:
                            await client.disconnect()
                            await asyncio.sleep(0)
                        except BaseException as exc:
                            if _should_reraise_base_exception(exc):
                                raise
                            disconnect_error = _format_probe_error(exc)
                            if best_connect_only is None:
                                best_connect_only = {
                                    "entry": entry,
                                    "ping_ms": None,
                                    "status": "fail",
                                    "error": f"disconnect failed: {disconnect_error}",
                                    "transport": transport_name,
                                    "dc_id": dc_id,
                                }
                            last_error = f"dc{dc_id}/{transport_name}: disconnect failed: {disconnect_error}"

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
        # Keep real loop crashes visible, but suppress known MTProto probe noise that the
        # checker already downgraded into a handled CONN/FAIL result.
        if _is_expected_mtproto_loop_noise(context):
            return
        current_loop.default_exception_handler(context)

    loop.set_exception_handler(_exception_handler)
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(_probe_mtproto_async(entry, runtime_cfg))
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except BaseException as exc:
            if _should_reraise_base_exception(exc):
                raise
            pass
        asyncio.set_event_loop(None)
        loop.close()


def run_mtproto_check(entries, runtime_cfg, log_func=None, progress_callback=None):
    ok, error = validate_runtime_config(runtime_cfg)
    if not ok:
        raise RuntimeError(error)

    resolved_crypto = configure_runtime_crypto_backend(runtime_cfg, entries=entries)
    runtime_cfg["_resolved_crypto_backend"] = resolved_crypto

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
        future_to_entry = {
            executor.submit(_probe_mtproto_sync, entry, runtime_cfg): entry
            for entry in entries
        }

        for future in as_completed(future_to_entry):
            entry = future_to_entry[future]
            try:
                result = future.result()
            except BaseException as exc:
                if _should_reraise_base_exception(exc):
                    raise
                result = {
                    "entry": entry,
                    "ping_ms": None,
                    "status": "fail",
                    "error": f"worker crash recovered: {_format_probe_error(exc)}",
                }
            all_results.append(result)

            entry = result["entry"]
            label = entry["label"]
            ping_ms = result["ping_ms"]
            error_reason = result["error"]
            proxy_kind = str(entry.get("proxy_kind") or "mtproto").lower()

            if ping_ms is not None:
                if result.get("status") == "connect_only":
                    if log_func:
                        log_func(
                            f"[cyan][CONN][/] [white]{label:<25}[/] | "
                            f"{ping_ms:>4}ms | {error_reason or 'RPC failed'} | {proxy_kind}"
                        )
                elif max_ping_ms and ping_ms > max_ping_ms:
                    result["status"] = "drop"
                    if log_func:
                        log_func(
                            f"[yellow][DROP][/] [white]{label:<25}[/] | "
                            f"{ping_ms:>4}ms > {max_ping_ms}ms | {proxy_kind}"
                        )
                else:
                    result["status"] = "live"
                    if log_func:
                        log_func(
                            f"[green][LIVE][/] [white]{label:<25}[/] | "
                            f"{ping_ms:>4}ms | {proxy_kind}"
                        )
                    current_live_results.append((entry.get("canonical_url", entry["original_url"]), ping_ms, 0.0))
            else:
                if result.get("status") == "proxy_unreachable":
                    if log_func:
                        log_func(
                            f"[yellow][UNREACH][/] [white]{label:<25}[/] | "
                            f"{error_reason or 'Proxy unreachable'} | {proxy_kind}"
                        )
                else:
                    result["status"] = "fail"
                    if log_func:
                        log_func(
                            f"[red][FAIL][/] [white]{label:<25}[/] | "
                            f"{error_reason or 'Unknown error'} | {proxy_kind}"
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
            "tg://proxy?server=104.253.134.194&port=443&secret=ee684d76827ec8317657e6f0eaa66ee67577622e7275",
            True,
        ),
        (
            "tg://proxy?server=example.com&port=443&secret=ABEiM0RVZneImaq7zN3u/w==",
            True,
        ),
        (
            "tg://proxy?server=example.com&port=443&secret=ABEiM0RVZneImaq7zN3u_w==",
            True,
        ),
        (
            "tg://proxy?server=example.com&port=443&secret=3QEjRWeJq83vASNFZ4mrze8=",
            True,
        ),
        (
            "tg://proxy?server=example.com&port=443&secret=7ptDuHVVv5Rk4Cvc0tuJMrB3d3cuc2l0ZS5jb20=",
            True,
        ),
        (
            "tg://proxy?server=example.com&port=443&secret=++/777777777777777777w==",
            True,
        ),
        (
            "tg://proxy?server=example.com&port=443&secret=--_777777777777777777w",
            True,
        ),
        (
            "https://t.me/proxy?server=example.com&port=443",
            False,
        ),
        (
            "tg://proxy?server=example.com&port=443&secret=ee0123456789abcdef0123456789abcdef",
            False,
        ),
        (
            "tg://proxy?server=example.com&port=443&secret=not-valid***",
            False,
        ),
        (
            "tg://socks?server=example.com&port=1080&user=alice&pass=secret",
            True,
        ),
        (
            "https://t.me/socks?server=example.com&port=1080",
            True,
        ),
    ]

    passed = 0
    for raw_url, should_pass in test_cases:
        parsed, _ = parse_mtproto_url(raw_url)
        is_ok = parsed is not None
        if is_ok == should_pass:
            passed += 1
            log_func(f"[green]Telegram proxy PASS[/]: {raw_url[:80]}")
        else:
            log_func(f"[red]Telegram proxy FAIL[/]: {raw_url[:80]}")

    total = len(test_cases)
    log_func(f"[bold]Telegram proxy self-test: {passed}/{total} passed[/]")
    return passed == total
