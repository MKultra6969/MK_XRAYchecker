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
# +═════════════════════════════════════════════════════════════════════════+
# ║                           VERSION 1.8.1                                 ║
# ║             В случае багов/недочётов создайте issue на github           ║
# ║                                                                         ║
# +═════════════════════════════════════════════════════════════════════════+


import argparse
import copy
import tempfile
import sys
import os
import shutil
import logging
import random
import time
import json
import socket
import subprocess
import platform
import base64
import requests
import psutil
import re
import stat
from datetime import datetime
from http.client import BadStatusLine, RemoteDisconnected
import urllib.parse
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import SimpleNamespace
from threading import Lock, Semaphore

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None
    YAML_AVAILABLE = False
YAML_WARNED = False

# ВЕРСИЯ СКРИПТА
# Формат: MAJOR.MINOR.PATCH (SemVer)
__version__ = "1.8.1"


def _ensure_utf8_stdio():
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_ensure_utf8_stdio()

# --- REALITY / FLOW validation ---
REALITY_PBK_RE = re.compile(r"^[A-Za-z0-9_-]{43,44}$")   # base64url publicKey
REALITY_SID_RE = re.compile(r"^[0-9a-fA-F]{0,32}$")      # shortId (hex, до 32 символов)

FLOW_ALIASES = {
    "xtls-rprx-visi": "xtls-rprx-vision",
}

FLOW_ALLOWED = {
    "",
    "xtls-rprx-vision",
}

# -------------------------------
# Shadowsocks method allowlists.
# Xray keeps the stricter subset to avoid Exit 23 on legacy stream ciphers.
SS_XRAY_ALLOWED_METHODS = {
    # Shadowsocks 2022
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",

    # AEAD
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",

    # Без шифрования
    "none",
    "plain",
}

# Mihomo accepts the Xray subset plus legacy methods that still appear in public
# subscriptions and are supported by Mihomo's Shadowsocks implementation.
SS_MIHOMO_ALLOWED_METHODS = SS_XRAY_ALLOWED_METHODS | {
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-192-gcm",
    "rc4-md5",
    "chacha20",
    "chacha20-ietf",
    "xchacha20",
    "xchacha20-ietf",
}

# Backward-compatible alias for existing Xray-oriented checks.
SS_ALLOWED_METHODS = SS_XRAY_ALLOWED_METHODS

def _normalize_ss_method(method):
    method_lower = (method or "").lower().strip()
    if method_lower == "chacha20-poly1305":
        return "chacha20-ietf-poly1305"
    if method_lower == "xchacha20-poly1305":
        return "xchacha20-ietf-poly1305"
    return method_lower

# -------------------------------

try:
    from art import text2art
except ImportError:
    text2art = None

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Aggregator Module ---
try:
    import aggregator
    AGGREGATOR_AVAILABLE = True
except ImportError:
    AGGREGATOR_AVAILABLE = False

# --- MTProto Checker Module ---
try:
    import mtproto_checker
    MTPROTO_AVAILABLE = True
except ImportError:
    mtproto_checker = None
    MTPROTO_AVAILABLE = False

# --- Self-Update Module ---
try:
    import updater
    UPDATER_AVAILABLE = True
    try:
        if os.environ.get("MKXRAY_SKIP_PENDING_APPLY") != "1" and updater.apply_pending_update_if_any():
            print("[UPDATER] Обновления применены. Перезапуск...")
            os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        print(f"[UPDATER] Предупреждение: Не удалось применить обновления: {e}")
except ImportError:
    UPDATER_AVAILABLE = False

# --- Xray Installer Module ---
try:
    import xray_installer
    XRAY_INSTALLER_AVAILABLE = True
except ImportError:
    XRAY_INSTALLER_AVAILABLE = False

# cfg
CONFIG_FILE = "config.json"
SOURCES_FILE = "sources.json"

# v1.1.3 Вероятно большинство ссылок ниже - мертвые.
# Стандартные истончники проксей (вероятно они уже устарели, поэтому просто для примера.)
DEFAULT_SOURCES_DATA = {
    "1": [
        "https://sub.amiralter.com/config", "https://itsyebekhe.github.io/PSG/", "https://f0rc3run.github.io/F0rc3Run-panel/", 
        "https://raw.githubusercontent.com/mermeroo/QX/main/Nodes", "https://raw.githubusercontent.com/Ashkan-m/v2ray/main/VIP.txt",
        "https://raw.githubusercontent.com/nscl5/5/main/configs/all.txt", "https://raw.githubusercontent.com/mermeroo/Loon/main/all.nodes.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/ss.txt", "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/ss",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/ss", "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix",
        "https://raw.githubusercontent.com/T3stAcc/V2Ray/main/All_Configs_Sub.txt", "https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub_all.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/vless.txt", "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/result/nodes",
        "https://raw.githubusercontent.com/misersun/config003/main/config_all.yaml", "https://raw.githubusercontent.com/penhandev/AutoAiVPN/main/allConfigs.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/config.txt", "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vless",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/configtg.txt", "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/vless",
        "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS/TrinityBase", "https://raw.githubusercontent.com/terik21/HiddifySubs-VlessKeys/main/6Satu",
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/ss.txt", "https://raw.githubusercontent.com/Danialsamadi/v2go/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt", "https://raw.githubusercontent.com/aqayerez/MatnOfficial-VPN/main/MatnOfficial",
        "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt", "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/ss_iran.txt",
        "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Vless.txt", "https://raw.githubusercontent.com/RaitonRed/ConfigsHub/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt", "https://raw.githubusercontent.com/skywrt/v2ray-configs/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links2.txt", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/ss.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt", "https://raw.githubusercontent.com/coldwater-10/V2rayCollector/main/vmess_iran.txt",
        "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt", "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vmess.txt",
        "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt", "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/ss.txt",
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt", "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/14.txt",
        "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/main/output_configs/USA.txt", "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt", "https://raw.githubusercontent.com/RaitonRed/ConfigsHub/main/Splitted-By-Protocol/ss.txt",
        "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vmess_configs.txt", "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
        "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vmess.txt", "https://raw.githubusercontent.com/mshojaei77/v2rayAuto/main/telegram/popular_channels_1",
        "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/main/output_configs/Vless.txt", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt",
        "https://raw.githubusercontent.com/kismetpro/NodeSuber/main/Splitted-By-Protocol/vless.txt", "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/itsyebekhe/PSG/main/config.txt", "https://github.com/4n0nymou3/multi-proxy-config-fetcher/raw/main/configs/proxy_configs.txt",
        "https://raw.githubusercontent.com/RaitonRed/ConfigsHub/main/Splitted-By-Protocol/vless.txt", "https://raw.githubusercontent.com/RaitonRed/ConfigsHub/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt", "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/shadowsocks.txt", "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/main/output_configs/ShadowSocks.txt",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt", "https://raw.githubusercontent.com/Firmfox/Proxify/main/v2ray_configs/seperated_by_protocol/shadowsocks.txt",
        "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha-All-Type.txt"
    ],
    "2": [
        "https://raw.githubusercontent.com/NiREvil/vless/main/sub/SSTime", "https://raw.githubusercontent.com/nscl5/5/main/configs/vmess.txt",
        "https://raw.githubusercontent.com/HakurouKen/free-node/main/public", "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Vless",
        "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/ss", "https://raw.githubusercontent.com/mfuu/v2ray/master/merge/merge.txt",
        "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Reality", "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
        "https://raw.githubusercontent.com/VpnNetwork01/vpn-net/main/README.md", "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/ssr.txt",
        "https://raw.githubusercontent.com/xiaoji235/airport-free/main/v2ray.txt", "https://raw.githubusercontent.com/penhandev/AutoAiVPN/main/AtuoAiVPN.txt",
        "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/vmess.txt", "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_vk.com.txt",
        "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt", "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
        "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/ndnode.txt", "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/wenode.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vmess", "https://raw.githubusercontent.com/SonzaiEkkusu/V2RayDumper/main/config.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/vmess", "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/tg-parser.py",
        "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix", "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/yudou66.txt",
        "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodefree.txt", "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/main-parser.py",
        "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_viber.com.txt", "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/vless",
        "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/vmess", "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/clashmeta.txt",
        "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodev2ray.txt", "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_TLS_vk.com.txt",
        "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_google.com.txt", "https://raw.githubusercontent.com/rango-cfs/NewCollector/main/v2ray_links.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt", "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/v2rayshare.txt",
        "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/vless.html", "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt",
        "https://raw.githubusercontent.com/Created-By/Telegram-Eag1e_YT/main/%40Eag1e_YT", "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/config_lite.txt",
        "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_telegram.org.txt", "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_whatsapp.com.txt",
        "https://raw.githubusercontent.com/skywrt/v2ray-configs/main/Config%20list15.txt", "https://raw.githubusercontent.com/skywrt/v2ray-configs/main/Config%20list49.txt",
        "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/main/xray_final.txt", "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links1.txt",
        "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Tr.txt", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Us.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/splitter.py", "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_TLS_viber.com.txt",
        "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/mix/sub.html", "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
        "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt", "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/backups/tg-parser_1",
        "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_TLS_google.com.txt", "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_activision.com.txt",
        "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_css.rbxcdn.com.txt", "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt", "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/shadowsocks",
        "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Hysteria2.txt", "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/mixed_iran.txt",
        "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Mix/mix.txt", "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/backups/main-parser_1",
        "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_TLS_telegram.org.txt", "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_whatsapp.com.txt",
        "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_activision.com.txt", "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_TLS_css.rbxcdn.com.txt",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt", "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_speedtest.tinkoff.ru.txt",
        "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/ss.txt", "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt",
        "https://raw.githubusercontent.com/skywrt/v2ray-configs/main/Splitted-By-Protocol/vmess.txt", "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vless.txt",
        "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vmess.txt", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Liechtenstein.txt",
        "https://raw.githubusercontent.com/Syavar/V2ray-Configs/main/OK_TLS_speedtest.tinkoff.ru.txt", "https://raw.githubusercontent.com/Firmfox/Proxify/main/v2ray_configs/mixed/subscription-2.txt",
        "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/North_Macedonia.txt", "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/main/output_configs/Turkmenistan.txt",
        "https://raw.githubusercontent.com/MrAbolfazlNorouzi/iran-configs/main/configs/working-configs.txt", "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha.txt",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub1.txt", "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/main/category/xhttp.txt",
        "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/main/category/httpupgrade.txt", "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
        "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/actives.txt"
    ]
}

DEFAULT_CONFIG = {
    "core_path": "xray",  # путь до ядра, просто xray если лежит в обнимку с скриптом
    "threads": 20,        # Потоки
    "proxies_per_batch": 50, # Сколько проксей обрабатывает ОДНО ядро
    "max_internal_threads": 50, # Сколько ПАРАЛЛЕЛЬНЫХ проверок идет внутри одного ядра
    "timeout": 3,         # Таймаут (повышать в случае огромного пинга)
    "local_port_start": 10000, # Отвечает за то, с какого конкретно порта будут запускаться ядра, 1080 > 1081 > 1082 = три потока(три ядра)
    "test_domain": "https://www.google.com/generate_204", # Ссылка по которой будут чекаться прокси, можно использовать другие в случае блокировок в разных странах.(http://cp.cloudflare.com/generate_204)
    "output_file": "sortedProxy.txt", # имя файла с отфильтрованными проксями
    "core_startup_timeout": 2.5, # Максимальное время ожидания старта ядра(ну если тупит)
    "core_kill_delay": 0.05,     # Задержка после УБИЙСТВА
    "core_cleanup_mode": "owned", # Очистка старых процессов: owned | all | none
    "router_mode": False,         # Безопасный режим для роутеров/OpenWRT (не трогать чужие процессы)
    "shuffle": False,
    "check_speed": False,
    "sort_by": "ping",           # ping | speed

    "speed_check_threads": 3, 
    "speed_test_url": "https://speed.cloudflare.com/__down?bytes=10000000", # Ссылка для скачивания
    "speed_download_timeout": 10, # Макс. время (сек) на скачивание файла (Чем больше - Тем точнее замеры.)
    "speed_connect_timeout": 5,   # Макс. время (сек) на подключение перед скачиванием (пинг 4000мс, скрипт ждёт 5000мс, значит скорость будет замеряна.)
    "speed_max_mb": 10,           # Лимит скачивания в МБ (чтобы не тратить трафик)
    "speed_min_kb": 1,            # Минимальный порог данных (в Килобайтах). Если прокси скачал меньше этого, скорость будет равной 0.0

    "speed_targets": [
        "https://speed.cloudflare.com/__down?bytes=20000000",              # Cloudflare (Global)
        "https://proof.ovh.net/files/100Mb.dat",                           # OVH (Europe/Global)
        "http://speedtest.tele2.net/100MB.zip",                            # Tele2 (Very stable)
        "https://speed.hetzner.de/100MB.bin",                              # Hetzner (Germany)
        "https://mirror.leaseweb.com/speedtest/100mb.bin",                 # Leaseweb (NL)
        "http://speedtest-ny.turnkeyinternet.net/100mb.bin",               # USA
        "https://yandex.ru/internet/api/v0/measure/download?size=10000000" # Yandex (RU/CIS)
    ],


    "sources": {}, # Переезд в отделный .json
    
    # Debug mode: при True используется proxies_per_batch=1 и threads=1
    # для быстрого поиска проблемной ссылки
    "debug_mode": False,
    
    # САМООБНОВЛЕНИЕ СКРИПТА
    # autoupdate: True = автоматически обновлять без вопросов
    #             False = спрашивать пользователя перед обновлением
    "autoupdate": False,
    
    # Настройки GitHub репозитория для обновлений
    # Можно поменять на свой форк если нужно
    "repo_owner": "MKultra6969",
    "repo_name": "MK_XRAYchecker",
    "repo_branch": "main",

    # АВТОУСТАНОВКА ЯДРА
    # autoinstall_xray: True = автоматически скачать и установить Xray если не найден
    #                   False = спрашивать пользователя
    "autoinstall_xray": True,
    
    # xray_version: "latest" или конкретная версия типа "v1.8.10"
    "xray_version": "latest",

    # Предпочитаемое ядро: auto | xray | mihomo
    "preferred_core": "auto",

    # Версия mihomo для автоустановки: "latest" или конкретный тег
    "mihomo_version": "latest",

    # autoinstall_mihomo: True = автоматически скачать и установить mihomo если не найден
    "autoinstall_mihomo": True,

    # Максимальный ping (мс) для отсева. 0 = не фильтровать по ping.
    "max_ping_ms": 666,

    # Агрегатор: предфильтр по странам (ISO2) до массовой GeoIP-проверки.
    "agg_countries": [],

    # MTProto checker: отдельный режим для Telegram proxy (tg://proxy / t.me/proxy)
    "mtproto": {
        "enabled": True,
        "api_id": 0,
        "api_hash": "",
        "threads": 20,
        "timeout": 5,
        "max_ping_ms": 666,
        "dc_probe_limit": 3,
        "crypto_backend": "auto",
        "probe_policy": "balanced",
        "connect_retries": 1,
        "rpc_retries": 1,
        "fetch_promo_data": True,
        "promo_session_file": "mtproto_promo",
        "promo_output_file": "sortedMtproto.promo.json",
        "promo_threads": 3,
        "promo_timeout": 6,
        "promo_probe_limit": 50,
        "save_connect_only": True,
        "connect_only_output_file": "sortedMtproto.conn.txt",
        "debug_attempts": False,
        "attempts_output_file": "sortedMtproto.attempts.json",
        "output_file": "sortedMtproto.txt"
    }
}


def _merge_with_defaults(defaults, user_data):
    result = copy.deepcopy(defaults)
    missing_keys = False

    if not isinstance(user_data, dict):
        return result, True

    for key, default_value in defaults.items():
        if key not in user_data:
            missing_keys = True
            continue

        user_value = user_data.get(key)
        if isinstance(default_value, dict):
            if isinstance(user_value, dict):
                merged_value, nested_missing = _merge_with_defaults(default_value, user_value)
                result[key] = merged_value
                if nested_missing:
                    missing_keys = True
            else:
                missing_keys = True
        else:
            result[key] = user_value

    for key, user_value in user_data.items():
        if key not in defaults:
            result[key] = user_value

    return result, missing_keys


def get_mtproto_config(cfg=None):
    source = cfg if isinstance(cfg, dict) else GLOBAL_CFG
    base = copy.deepcopy(DEFAULT_CONFIG.get("mtproto", {}))
    user_value = source.get("mtproto", {}) if isinstance(source, dict) else {}
    merged, _ = _merge_with_defaults(base, user_value)
    return merged

def load_sources():
    if os.path.exists(SOURCES_FILE):
        try:
            with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            print(f"Error loading {SOURCES_FILE}: {e}")
    
    try:
        with open(SOURCES_FILE, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_SOURCES_DATA, f, indent=4)
        print(f"Created default {SOURCES_FILE}")
    except Exception as e:
        print(f"Error creating {SOURCES_FILE}: {e}")
    
    return DEFAULT_SOURCES_DATA

def load_config():
    loaded_sources = load_sources()

    if not os.path.exists(CONFIG_FILE):
        try:
            config_to_write = copy.deepcopy(DEFAULT_CONFIG)
            del config_to_write["sources"] 
            
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config_to_write, f, indent=4)
            print(f"Created default {CONFIG_FILE}")
        except: pass
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["sources"] = loaded_sources
        return cfg
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
        
        config, has_new_keys = _merge_with_defaults(DEFAULT_CONFIG, user_config)
        
        config["sources"] = loaded_sources
        
        if has_new_keys:
            try:
                print(f">> Config update: added new keys to {CONFIG_FILE}...")
                save_cfg = copy.deepcopy(config)
                if "sources" in save_cfg: del save_cfg["sources"]
                
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(save_cfg, f, indent=4)
            except Exception as e:
                print(f"Warning: Не удалось обновить конфиг файл: {e}")

        return config
    except Exception as e:
        print(f"Error loading config: {e}")
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["sources"] = loaded_sources
        return cfg

GLOBAL_CFG = load_config()

PROTO_HINTS = ("vless://", "vmess://", "trojan://", "hysteria2://", "hy2://", "anytls://", "tuic://", "ss://", "ssr://", "hysteria://", "socks://", "socks5://", "socks5h://", "http://", "https://", "mierus://")

MIHOMO_NATIVE_TYPES = frozenset({
    "ss", "shadowsocks", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2",
    "anytls", "tuic", "socks5", "http", "https", "mieru", "wireguard", "ssh", "snell",
    "shadowquic", "sudoku", "masque", "trusttunnel", "openvpn", "tailscale",
})

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

URL_FINDER = re.compile(
    r'(?:hysteria2\+realm\+http|hysteria2\+realm|vless|vmess|trojan|hysteria2|hy2|anytls|tuic|ssr|hysteria|socks|socks5|socks5h|mierus)://[^\s"\'<>]+'
    r'|(?<![A-Za-z0-9+])ss://[^\s"\'<>]+'
    r'|https?://[^\s"\'<>/@]+@[^\s"\'<>/]+:\d+[^\s"\'<>]*',
    re.IGNORECASE
)

HTTP_URL_FINDER = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.prompt import Prompt, Confirm
    from rich.logging import RichHandler
    from rich import box
    from rich.text import Text
    console = Console()
except ImportError:
    print("Пожалуйста, установите библиотеку rich: pip install rich")
    sys.exit(1)

class Fore:
    CYAN = "[cyan]"
    GREEN = "[green]"
    RED = "[red]"
    YELLOW = "[yellow]"
    MAGENTA = "[magenta]"
    BLUE = "[blue]"
    WHITE = "[white]"
    LIGHTBLACK_EX = "[dim]"
    LIGHTGREEN_EX = "[bold green]"
    LIGHTRED_EX = "[bold red]"
    RESET = "[/]"

class Style:
    BRIGHT = "[bold]"
    RESET_ALL = "[/]"

def clean_url(url):
    """
    Нормализация URL: удаление BOM, невидимых символов,
    декодирование HTML entities (&amp; -> &) и URL encoding (%26 -> &).
    Делаем 2 прохода для вложенных экранирований типа &amp%3B или %26amp%3B.
    """
    url = url.strip()
    url = url.replace('\ufeff', '').replace('\u200b', '')
    url = url.replace('\n', '').replace('\r', '')
    
    url = html.unescape(url)
    url = urllib.parse.unquote(url)
    
    url = html.unescape(url)
    url = urllib.parse.unquote(url)
    
    return url


def normalize_http_url(url):
    """
    Нормализация HTTP(S) URL-подписок: удаление мусорного обрамления,
    которое часто остаётся при чтении JSON/Markdown/списков как обычного текста.
    """
    if not isinstance(url, str):
        return ""

    cleaned = clean_url(url).strip().strip("\"'<>")
    cleaned = cleaned.rstrip('"\',;)]}>')
    return cleaned if cleaned.lower().startswith(("http://", "https://")) else ""


def _iter_string_values(payload):
    if isinstance(payload, str):
        yield payload
        return
    if isinstance(payload, dict):
        for value in payload.values():
            yield from _iter_string_values(value)
        return
    if isinstance(payload, (list, tuple, set)):
        for item in payload:
            yield from _iter_string_values(item)

def _self_test_clean_url():
    test_cases = [
        ("vless://test@host:443?security=reality&amp;pbk=ABC&amp;sid=123", "security=reality&pbk=ABC&sid=123"),
        ("vless://test@host:443?security=reality&amp%3Bpbk=ABC", "security=reality&pbk=ABC"),
        ("vless://test@host:443?security=reality%26amp%3Bpbk=ABC", "security=reality&pbk=ABC"),
        ("vless://test@host:443?flow=xtls-rprx-vision&type=tcp", "flow=xtls-rprx-vision&type=tcp"),
    ]
    
    passed = 0
    for raw, expected in test_cases:
        cleaned = clean_url(raw)
        if "?" in cleaned:
            query = cleaned.split("?", 1)[1]
            params = urllib.parse.parse_qs(query)
            has_separate_keys = "security" in params or "pbk" in params or "flow" in params
            if has_separate_keys or expected in cleaned:
                passed += 1
                safe_print(f"[green]PASS[/]: {raw[:60]}...")
            else:
                safe_print(f"[red]FAIL[/]: {raw[:60]}...")
                safe_print(f"[dim]  Got: {cleaned[:100]}[/]")
        else:
            passed += 1
    
    safe_print(f"\n[bold]Self-test: {passed}/{len(test_cases)} passed[/]")
    return passed == len(test_cases)


def _self_test_subscription_url_parsing():
    test_url = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/10.txt"
    payload = json.dumps({"2": [test_url, f"{test_url[:-6]}11.txt"]})
    markdown_payload = f'- "{test_url}",\n'

    checks = [
        (
            "normalize_http_url trims JSON tail",
            normalize_http_url(f'"{test_url}",') == test_url,
        ),
        (
            "extract_subscription_urls parses JSON sources",
            extract_subscription_urls(payload) == sorted([test_url, f"{test_url[:-6]}11.txt"]),
        ),
        (
            "extract_subscription_urls trims markdown/list wrappers",
            extract_subscription_urls(markdown_payload) == [test_url],
        ),
    ]

    passed = 0
    for label, ok in checks:
        if ok:
            passed += 1
            safe_print(f"[green]PASS[/]: {label}")
        else:
            safe_print(f"[red]FAIL[/]: {label}")

    safe_print(f"\n[bold]Subscription URL self-test: {passed}/{len(checks)} passed[/]")
    return passed == len(checks)

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

class SmartLogger:
    def __init__(self, filename="checker_history.log"):
        self.filename = filename
        self.lock = Lock()
        try:
            with open(self.filename, 'a', encoding='utf-8') as f:
                f.write(
    f"\n{'-'*30} NEW SESSION v{__version__} "
    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {'-'*30}\n"
)
        except Exception as e:
            console.print(f"[bold red]Ошибка создания лога: {e}[/]")

    def log(self, msg, style=None):
        with self.lock:
            console.print(msg, style=style, highlight=False)

            try:
                text_obj = Text.from_markup(str(msg))
                clean_msg = text_obj.plain.strip()
                
                if clean_msg:
                    timestamp = datetime.now().strftime("[%H:%M:%S]")
                    log_line = f"{timestamp} {clean_msg}\n"
                    
                    with open(self.filename, 'a', encoding='utf-8') as f:
                        f.write(log_line)
            except Exception:
                pass

MAIN_LOGGER = SmartLogger("checker_history.log")

logging.basicConfig(format="%(asctime)s - %(message)s", level=logging.INFO, datefmt='%H:%M:%S')

def safe_print(msg):
    MAIN_LOGGER.log(msg)
    
def upload_log_to_service(is_crash=False):
    log_file = "checker_history.log"
    
    if not os.path.exists(log_file):
        console.print("[red]Файл лога не найден.[/]")
        return None
    
    console.print("[yellow]📤 Загрузка логов на paste.rs...[/]")
    
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            content = "".join(lines[-1000:])
        
        resp = requests.post(
            "https://paste.rs",
            data=content.encode('utf-8'),
            headers={"Content-Type": "text/plain"},
            timeout=15
        )
        
        if resp.status_code in (200, 201):
            url = resp.text.strip()
            console.print(Panel(
                f"[bold cyan]{url}[/]",
                title="✅ Upload Success",
                border_style="green"
            ))
            return url
        else:
            console.print(f"[red]❌ HTTP {resp.status_code}[/]")
            console.print(f"[dim]{resp.text[:200]}[/]")
                
    except Exception as e:
        console.print(f"[red]❌ Upload failed: {e}[/]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()[:500]}[/]")
    
    return None

def init_temp_dir():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    preferred = os.path.join(script_dir, ".tmp_runtime")

    for candidate in (preferred, tempfile.mkdtemp(prefix="mkxray_")):
        try:
            os.makedirs(candidate, exist_ok=True)
            probe = os.path.join(candidate, ".write_probe")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(probe)
            return candidate
        except Exception:
            continue

    return script_dir

TEMP_DIR = init_temp_dir()
OS_SYSTEM = platform.system().lower()
CORE_PATH = ""
CORE_FLAVOR = "xray"
CTRL_C = False

LOGO_FONTS = [
    "cybermedium",
    "4Max"
]

BACKUP_LOGO = r"""
+═════════════════════════════════════════════════════════════════════════+
║      ███▄ ▄███▓ ██ ▄█▀ █    ██  ██▓    ▄▄▄█████▓ ██▀███   ▄▄▄           ║
║     ▓██▒▀█▀ ██▒ ██▄█▒  ██  ▓██▒▓██▒    ▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄         ║
║     ▓██    ▓██░▓███▄░ ▓██  ▒██░▒██░    ▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄       ║
║     ▒██    ▒██ ▓██ █▄ ▓▓█  ░██░▒██░    ░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██      ║
║     ▒██▒   ░██▒▒██▒ █▄▒▒█████▓ ░██████▒  ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒     ║
║     ░ ▒░   ░  ░▒ ▒▒ ▓▒░▒▓▒ ▒ ▒ ░ ▒░▓  ░  ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░     ║
║     ░  ░      ░░ ░▒ ▒░░░▒░ ░ ░ ░ ░ ▒  ░    ░      ░▒ ░ ▒░  ▒   ▒▒ ░     ║
║     ░      ░   ░ ░░ ░  ░░░ ░ ░   ░ ░     ░        ░░   ░   ░   ▒        ║
║            ░   ░  ░      ░         ░  ░            ░           ░  ░     ║
║                                                                         ║
+═════════════════════════════════════════════════════════════════════════+
║                               MKultra69                                 ║
+═════════════════════════════════════════════════════════════════════════+
"""

# ------------------------------ ДАЛЬШЕ БОГА НЕТ ------------------------------

def is_port_in_use(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except:
        return False


def wait_for_core_start(port, max_wait):
    start_time = time.time()
    while time.time() - start_time < max_wait:
        if is_port_in_use(port):
            return True
        time.sleep(0.05) 
    return False

def detect_core_flavor(core_path):
    if not core_path:
        return "xray"

    lower_name = os.path.basename(core_path).lower()
    if "mihomo" in lower_name or "clash" in lower_name:
        return "mihomo"
    if "xray" in lower_name or "v2ray" in lower_name:
        return "xray"

    for probe_cmd in ([core_path, "-v"], [core_path, "version"]):
        try:
            result = subprocess.run(
                probe_cmd,
                capture_output=True,
                text=True,
                timeout=3
            )
            output = f"{result.stdout}\n{result.stderr}".lower()
            if "mihomo" in output or "clash" in output:
                return "mihomo"
            if "xray" in output or "v2ray" in output:
                return "xray"
        except Exception:
            pass

    return "xray"

XRAY_CORE_CANDIDATES = ["xray.exe", "xray", "v2ray.exe", "v2ray", "bin/xray.exe", "bin/xray"]
MIHOMO_CORE_CANDIDATES = ["mihomo.exe", "mihomo", "clash-meta.exe", "clash-meta", "bin/mihomo.exe", "bin/mihomo"]
ALL_CORE_PROCESS_NAMES = (
    "xray.exe", "v2ray.exe", "xray", "v2ray",
    "mihomo.exe", "mihomo", "clash-meta.exe", "clash-meta"
)
VALID_CLEANUP_MODES = {"owned", "all", "none"}

def build_core_candidates(engine_mode):
    mode = str(engine_mode or "auto").strip().lower()
    if mode == "xray":
        return list(XRAY_CORE_CANDIDATES)
    if mode == "mihomo":
        return list(MIHOMO_CORE_CANDIDATES)
    return XRAY_CORE_CANDIDATES + MIHOMO_CORE_CANDIDATES

def normalize_cleanup_mode(mode, default="owned"):
    normalized = str(mode or default).strip().lower()
    if normalized not in VALID_CLEANUP_MODES:
        return default
    return normalized

def build_core_process_targets(core_path):
    target_names = set(ALL_CORE_PROCESS_NAMES)
    core_name = os.path.basename(core_path or "").strip().lower()
    if core_name:
        target_names.add(core_name)
    return target_names

def process_looks_checker_owned(proc):
    try:
        cmdline = proc.info.get('cmdline') if hasattr(proc, "info") else None
        if cmdline is None:
            cmdline = proc.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False
    except Exception:
        return False

    lowered = [str(part).lower() for part in (cmdline or []) if part]
    if not lowered:
        return False

    has_batch_cfg = any(
        ("batch_" in part) and (part.endswith(".json") or part.endswith(".yaml") or part.endswith(".yml"))
        for part in lowered
    )
    if not has_batch_cfg:
        return False

    temp_markers = {".tmp_runtime", "mkxray_"}
    temp_tail = os.path.basename(TEMP_DIR).lower()
    if temp_tail:
        temp_markers.add(temp_tail)

    return any(any(marker in part for marker in temp_markers) for part in lowered)

def cleanup_stale_cores(core_path, cleanup_mode):
    mode = normalize_cleanup_mode(cleanup_mode)
    if mode == "none":
        return 0, 0, mode

    target_names = build_core_process_targets(core_path)
    killed_count = 0
    skipped_foreign = 0

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            proc_name = (proc.info.get('name') or "").lower()
            if not proc_name or proc_name not in target_names:
                continue

            if mode == "owned" and not process_looks_checker_owned(proc):
                skipped_foreign += 1
                continue

            proc.kill()
            killed_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return killed_count, skipped_foreign, mode

def save_main_config(cfg):
    try:
        save_cfg = cfg.copy()
        if "sources" in save_cfg:
            del save_cfg["sources"]
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(save_cfg, f, indent=4)
        return True, None
    except Exception as e:
        return False, e


def split_list(lst, n):
    if n <= 0: return []
    k, m = divmod(len(lst), n)
    return (lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

def _looks_like_subscription_payload(text):
    low = (text or "").lower()
    return (
        "proxies:" in low or
        "proxy-providers:" in low or
        "\"proxies\"" in low or
        "'proxies'" in low
    )

def try_decode_base64(text):
    raw = text.strip()
    if not raw:
        return raw

    if any(marker in raw for marker in PROTO_HINTS):
        return raw

    compact = re.sub(r'\s+', '', raw)
    if not compact or not set(compact) <= BASE64_CHARS:
        return raw

    missing_padding = len(compact) % 4
    if missing_padding:
        compact += "=" * (4 - missing_padding)

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(compact).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if any(marker in decoded for marker in PROTO_HINTS) or _looks_like_subscription_payload(decoded):
            return decoded
    return raw

def _payload_variants(blob):
    clean_blob = blob.strip()
    if not clean_blob:
        return set()

    variants = {clean_blob}
    
    decoded_blob = try_decode_base64(clean_blob)
    
    if decoded_blob and decoded_blob != clean_blob:
        variants.add(decoded_blob)
    for line in clean_blob.splitlines():
        line = line.strip()
        if not line:
            continue
        maybe_decoded = try_decode_base64(line)
        if maybe_decoded and maybe_decoded != line:
            variants.add(maybe_decoded)
            
    return variants

def _first_scalar(value, default=""):
    if isinstance(value, list):
        for item in value:
            if item not in (None, ""):
                return str(item)
        return default
    if value in (None, ""):
        return default
    return str(value)

def _bool_value(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off"):
            return False
    return default

def _sanitize_yaml_text(payload):
    # Некоторые провайдеры отдают YAML с C1 control chars (0x80-0x9F),
    # что ломает safe_load. Удаляем только невалидные управляющие символы.
    out = []
    for ch in payload:
        code = ord(ch)
        if ch in ("\n", "\r", "\t"):
            out.append(ch)
            continue
        if code < 0x20:
            continue
        if 0x7F <= code <= 0x9F:
            continue
        out.append(ch)
    return "".join(out)

def _parse_network_fields(proxy):
    network = str(proxy.get("network", "tcp") or "tcp").strip().lower()
    if not network:
        network = "tcp"

    path = ""
    host = ""
    service_name = ""

    if network == "ws":
        ws_opts = proxy.get("ws-opts", {}) if isinstance(proxy.get("ws-opts"), dict) else {}
        path = _first_scalar(ws_opts.get("path"), "/")
        headers = ws_opts.get("headers", {}) if isinstance(ws_opts.get("headers"), dict) else {}
        host = _first_scalar(headers.get("Host"), "")
        if _bool_value(ws_opts.get("v2ray-http-upgrade"), False):
            network = "httpupgrade"

    elif network == "http":
        http_opts = proxy.get("http-opts", {}) if isinstance(proxy.get("http-opts"), dict) else {}
        path = _first_scalar(http_opts.get("path"), "/")
        headers = http_opts.get("headers", {}) if isinstance(http_opts.get("headers"), dict) else {}
        host = _first_scalar(headers.get("Host"), "")

    elif network == "h2":
        h2_opts = proxy.get("h2-opts", {}) if isinstance(proxy.get("h2-opts"), dict) else {}
        path = _first_scalar(h2_opts.get("path"), "/")
        host = _first_scalar(h2_opts.get("host"), "")

    elif network == "grpc":
        grpc_opts = proxy.get("grpc-opts", {}) if isinstance(proxy.get("grpc-opts"), dict) else {}
        service_name = _first_scalar(grpc_opts.get("grpc-service-name"), "")

    return network, path, host, service_name

def _build_subscription_vmess(proxy):
    server = _first_scalar(proxy.get("server"), "")
    port = proxy.get("port")
    uuid = _first_scalar(proxy.get("uuid"), "")
    if not server or not is_valid_port(port) or not is_valid_uuid(uuid):
        return None

    network, path, host, service_name = _parse_network_fields(proxy)
    tls = _bool_value(proxy.get("tls"), False)
    sni = _first_scalar(proxy.get("servername"), "") or _first_scalar(proxy.get("sni"), "")
    fp = _first_scalar(proxy.get("client-fingerprint"), "")
    alpn_raw = proxy.get("alpn")
    if isinstance(alpn_raw, list):
        alpn = ",".join([str(x) for x in alpn_raw if x])
    else:
        alpn = _first_scalar(alpn_raw, "")

    node = {
        "v": "2",
        "ps": _first_scalar(proxy.get("name"), "vmess"),
        "add": server,
        "port": str(int(port)),
        "id": uuid,
        "aid": str(int(proxy.get("alterId", 0) or 0)),
        "scy": _first_scalar(proxy.get("cipher"), "auto"),
        "net": network,
        "path": path,
        "host": host,
        "tls": "tls" if tls else "",
        "sni": sni,
        "fp": fp,
        "alpn": alpn
    }
    if service_name:
        node["serviceName"] = service_name
    encoded = base64.b64encode(json.dumps(node, separators=(",", ":")).encode("utf-8")).decode("utf-8")
    return f"vmess://{encoded}"

def _build_subscription_vless(proxy):
    server = _first_scalar(proxy.get("server"), "")
    port = proxy.get("port")
    uuid = _first_scalar(proxy.get("uuid"), "")
    if not server or not is_valid_port(port) or not is_valid_uuid(uuid):
        return None

    network, path, host, service_name = _parse_network_fields(proxy)
    reality_opts = proxy.get("reality-opts", {}) if isinstance(proxy.get("reality-opts"), dict) else {}
    has_reality = bool(_first_scalar(reality_opts.get("public-key"), ""))
    if has_reality:
        security = "reality"
    elif _bool_value(proxy.get("tls"), False):
        security = "tls"
    else:
        security = "none"

    query = {
        "type": network,
        "security": security,
    }
    if path:
        query["path"] = path
    if host:
        query["host"] = host
    if service_name:
        query["serviceName"] = service_name

    sni = _first_scalar(proxy.get("servername"), "") or _first_scalar(proxy.get("sni"), "")
    fp = _first_scalar(proxy.get("client-fingerprint"), "")
    alpn_raw = proxy.get("alpn")
    if isinstance(alpn_raw, list):
        alpn = ",".join([str(x) for x in alpn_raw if x])
    else:
        alpn = _first_scalar(alpn_raw, "")

    if sni:
        query["sni"] = sni
    if fp:
        query["fp"] = fp
    if alpn:
        query["alpn"] = alpn

    flow = _first_scalar(proxy.get("flow"), "")
    if flow:
        query["flow"] = flow

    pbk = _first_scalar(reality_opts.get("public-key"), "")
    sid = _first_scalar(reality_opts.get("short-id"), "")
    if pbk:
        query["pbk"] = pbk
    if sid:
        query["sid"] = sid

    q = urllib.parse.urlencode(query, doseq=False)
    tag = urllib.parse.quote(_first_scalar(proxy.get("name"), "vless"))
    return f"vless://{uuid}@{server}:{int(port)}?{q}#{tag}"

def _build_subscription_trojan(proxy):
    server = _first_scalar(proxy.get("server"), "")
    port = proxy.get("port")
    password = _first_scalar(proxy.get("password"), "")
    if not server or not is_valid_port(port) or not password:
        return None

    network, path, host, service_name = _parse_network_fields(proxy)
    query = {"type": network}
    if _bool_value(proxy.get("tls"), True):
        query["security"] = "tls"
    sni = _first_scalar(proxy.get("servername"), "") or _first_scalar(proxy.get("sni"), "")
    if sni:
        query["sni"] = sni
    if path:
        query["path"] = path
    if host:
        query["host"] = host
    if service_name:
        query["serviceName"] = service_name
    fp = _first_scalar(proxy.get("client-fingerprint"), "")
    if fp:
        query["fp"] = fp

    q = urllib.parse.urlencode(query, doseq=False)
    tag = urllib.parse.quote(_first_scalar(proxy.get("name"), "trojan"))
    return f"trojan://{urllib.parse.quote(password, safe='')}@{server}:{int(port)}?{q}#{tag}"

def _build_subscription_ss(proxy):
    server = _first_scalar(proxy.get("server"), "")
    port = proxy.get("port")
    cipher = _first_scalar(proxy.get("cipher"), "")
    password = _first_scalar(proxy.get("password"), "")
    if not server or not is_valid_port(port) or not cipher or not password:
        return None

    auth = f"{cipher}:{password}"
    encoded = base64.urlsafe_b64encode(auth.encode("utf-8")).decode("utf-8").rstrip("=")
    tag = urllib.parse.quote(_first_scalar(proxy.get("name"), "ss"))
    return f"ss://{encoded}@{server}:{int(port)}#{tag}"

def _build_subscription_hysteria2(proxy):
    server = _first_scalar(proxy.get("server"), "")
    port = proxy.get("port")
    password = _first_scalar(proxy.get("password"), "") or _first_scalar(proxy.get("auth-str"), "")
    if not server or not is_valid_port(port) or not password:
        return None

    query = {}
    sni = _first_scalar(proxy.get("sni"), "") or _first_scalar(proxy.get("servername"), "")
    if sni:
        query["sni"] = sni
    if _bool_value(proxy.get("skip-cert-verify"), False):
        query["insecure"] = "1"

    obfs = _first_scalar(proxy.get("obfs"), "")
    obfs_password = _first_scalar(proxy.get("obfs-password"), "")
    if obfs:
        query["obfs"] = obfs
        if obfs_password:
            query["obfs-password"] = obfs_password

    q = urllib.parse.urlencode(query, doseq=False)
    tag = urllib.parse.quote(_first_scalar(proxy.get("name"), "hy2"))
    if q:
        return f"hysteria2://{urllib.parse.quote(password, safe='')}@{server}:{int(port)}?{q}#{tag}"
    return f"hysteria2://{urllib.parse.quote(password, safe='')}@{server}:{int(port)}#{tag}"

def _extract_subscription_links(payload):
    global YAML_WARNED
    if not YAML_AVAILABLE:
        if _looks_like_subscription_payload(payload) and not YAML_WARNED:
            YAML_WARNED = True
            safe_print("[yellow]Для парсинга Clash/Mihomo YAML-подписок установите PyYAML: pip install pyyaml[/]")
        return []
    if not _looks_like_subscription_payload(payload):
        return []
    sanitized_payload = _sanitize_yaml_text(payload)
    if not sanitized_payload.strip():
        return []
    try:
        data = yaml.safe_load(sanitized_payload)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    proxies = data.get("proxies")
    if not isinstance(proxies, list):
        return []

    links = []
    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        ptype = _first_scalar(proxy.get("type"), "").lower()
        if not ptype:
            continue
        native = copy.deepcopy(proxy)
        native["_native_mihomo"] = True
        if ptype not in MIHOMO_NATIVE_TYPES:
            native["_unsupported"] = f"unknown Mihomo proxy type: {ptype}"
        links.append(native)
    return links
def _merge_proxy_entries(mapping, entries):
    for entry in entries:
        mapping[canonical_proxy_key(entry)] = entry
def parse_content(text):
    # ponytail: canonical dedupe via parsed-proxy key (drops query order/trash/fragment)
    seen = {}
    raw_hits = 0

    for line in str(text or "").splitlines():
        try:
            native = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(native, dict) and native.get("type"):
            native["_native_mihomo"] = True
            if str(native["type"]).lower() not in MIHOMO_NATIVE_TYPES:
                native["_unsupported"] = f"unknown Mihomo proxy type: {native['type']}"
            seen[canonical_proxy_key(native)] = native
            raw_hits += 1

    for payload in _payload_variants(text):
        sub_links = _extract_subscription_links(payload)
        if sub_links:
            raw_hits += len(sub_links)
            for item in sub_links:
                if isinstance(item, dict):
                    seen[canonical_proxy_key(item)] = item
                    continue
                cleaned = html.unescape(item.rstrip(';,)]}').strip())
                if cleaned and len(cleaned) > 15:
                    seen[canonical_proxy_key(cleaned)] = cleaned

        matches = URL_FINDER.findall(payload)
        raw_hits += len(matches)
        for item in matches:
            cleaned = html.unescape(item.rstrip(';,)]}').strip())
            if cleaned and len(cleaned) > 15:
                if cleaned.lower().startswith("mierus://"):
                    expanded = parse_mierus_entries(cleaned)
                    if expanded:
                        raw_hits += len(expanded) - 1
                        for native in expanded:
                            seen[canonical_proxy_key(native)] = native
                        continue
                seen[canonical_proxy_key(cleaned)] = cleaned

    return list(seen.values()), raw_hits or len(seen)

def _is_authenticated_http_proxy(value):
    try:
        return "@" in urllib.parse.urlsplit(value).netloc and parse_mihomo_auth_uri(value) is not None
    except Exception:
        return False

def extract_subscription_urls(text):
    urls = set()

    raw_text = text or ""
    stripped = raw_text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            payload = json.loads(raw_text)
        except Exception:
            payload = None
        if payload is not None:
            for value in _iter_string_values(payload):
                if _is_authenticated_http_proxy(value):
                    continue
                cleaned = normalize_http_url(value)
                if cleaned:
                    urls.add(cleaned)
                    continue
                for match in HTTP_URL_FINDER.findall(value):
                    if _is_authenticated_http_proxy(match):
                        continue
                    cleaned = normalize_http_url(match)
                    if cleaned:
                        urls.add(cleaned)

    for match in HTTP_URL_FINDER.findall(raw_text):
        if _is_authenticated_http_proxy(match):
            continue
        cleaned = normalize_http_url(match)
        if cleaned:
            urls.add(cleaned)

    return sorted(urls)

def fetch_url(url):
    try:
        raw_url = url
        url = normalize_http_url(url)
        if not url:
            safe_print(f"{Fore.RED}>> Некорректный URL подписки: {raw_url}{Style.RESET_ALL}")
            return []
        safe_print(f"{Fore.CYAN}>> Загрузка URL: {url}{Style.RESET_ALL}")
        resp = requests.get(url, timeout=15, verify=False)
        if resp.status_code == 200:
            links, count = parse_content(resp.text)
            return links
        else:
            safe_print(f"{Fore.RED}>> Ошибка скачивания: HTTP {resp.status_code}{Style.RESET_ALL}")
    except Exception as e:
        safe_print(f"{Fore.RED}>> Ошибка URL: {e}{Style.RESET_ALL}")
    return []
    
def _uri_parts(url, schemes, known=(), repeat=(), default_port=443):
    """Parse proxy URIs once; query decoding deliberately keeps '+' in credentials."""
    try:
        # clean_url() decodes the whole URI and would turn encoded @/&/# into syntax.
        raw_url = html.unescape(str(url).strip().replace("\ufeff", "").replace("\u200b", "").replace("\n", "").replace("\r", ""))
        parsed = urllib.parse.urlsplit(raw_url)
        if parsed.scheme.lower() not in schemes or not parsed.hostname:
            return None
        try:
            port = parsed.port or default_port
            authority_ports = ""
        except ValueError:  # Hysteria2 port hopping lives in the URI authority.
            if parsed.scheme.lower() not in ("hysteria2", "hy2"):
                return None
            authority = parsed.netloc.rsplit("@", 1)[-1]
            port_text = authority.rsplit(":", 1)[-1]
            ranges = port_text.split(",")
            if not ranges:
                return None
            for item in ranges:
                bounds = item.split("-", 1)
                if any(not is_valid_port(bound) for bound in bounds) or (len(bounds) == 2 and int(bounds[0]) > int(bounds[1])):
                    return None
            first_port = ranges[0].split("-", 1)[0]
            port, authority_ports = int(first_port), port_text
        if not is_valid_port(port):
            return None
        values, unknown = {}, []
        for item in filter(None, parsed.query.split("&")):
            key, sep, value = item.partition("=")
            key, value = urllib.parse.unquote(key), urllib.parse.unquote(value if sep else "")
            if key in values and key in known and key not in repeat:
                return None
            if key in known:
                values.setdefault(key, []).append(value)
            else:
                unknown.append(f"{key}={value}" if sep else key)
        if authority_ports:
            values["_authority_ports"] = [authority_ports]
        raw_userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
        return parsed, values, unknown, raw_userinfo, port
    except Exception:
        return None

def _uri_value(values, *keys, default=""):
    for key in keys:
        if values.get(key):
            return values[key][0].strip()
    return default

def _b64url_length(value, length):
    try:
        return bool(re.fullmatch(r"[A-Za-z0-9_-]+", value)) and len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))) == length
    except Exception:
        return False

def _valid_vless_encryption(value):
    if value == "none":
        return True
    parts = value.split(".")
    if len(parts) < 4 or parts[0] != "mlkem768x25519plus" or parts[1] not in ("native", "xorpub", "random") or parts[2] not in ("0rtt", "1rtt"):
        return False
    keys_started = False
    max_padding = 0
    for index, part in enumerate(parts[3:]):
        if len(part) >= 20:
            keys_started = True
            if not (_b64url_length(part, 32) or _b64url_length(part, 1184)):
                return False
            continue
        if keys_started or not re.fullmatch(r"\d+-\d+-\d+", part):
            return False
        chance, low, high = map(int, part.split("-"))
        if chance > 100 or low > high or (index == 0 and (chance < 100 or min(low, high) < 35)):
            return False
        if index % 2 == 0:
            max_padding += high
            if max_padding > 65553:
                return False
    return keys_started

def parse_vless(url):
    known = ("encryption", "security", "sni", "fp", "pbk", "sid", "type", "flow", "path", "host", "alpn", "serviceName", "mode", "headerType", "spx", "spiderX", "pqv", "pcs", "packetEncoding", "packet-encoding", "ed", "ech", "fm", "extra", "vcn")
    uri = _uri_parts(url, ("vless",), known)
    if not uri:
        return None
    parsed, params, unknown, userinfo, port = uri
    uuid = urllib.parse.unquote(userinfo)
    pbk, sid, pqv = _uri_value(params, "pbk"), _uri_value(params, "sid"), _uri_value(params, "pqv")
    if pbk and not _b64url_length(pbk, 32):
        return None
    if sid and (not re.fullmatch(r"[0-9a-fA-F]{0,16}", sid) or len(sid) % 2):
        return None
    if pqv and not _b64url_length(pqv, 1952):
        return None
    pcs = _uri_value(params, "pcs")
    if pcs and any(not re.fullmatch(r"[0-9a-fA-F]{64}", pin) for pin in pcs.split(",")):
        return None
    spx = _uri_value(params, "spx", "spiderX", default="/")
    if not spx.startswith("/"):
        return None
    encryption = _uri_value(params, "encryption", default="none")
    if not _valid_vless_encryption(encryption):
        return None
    def json_object(key):
        value = _uri_value(params, key)
        if not value:
            return None
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, dict) else False
        except (TypeError, ValueError):
            return False
    fm, extra = json_object("fm"), json_object("extra")
    if fm is False or extra is False:
        return None
    raw_net_type = _uri_value(params, "type", default="tcp").lower()
    net_type = {"tcp": "raw", "splithttp": "xhttp", "mkcp": "kcp"}.get(raw_net_type, raw_net_type)
    flow = FLOW_ALIASES.get(_uri_value(params, "flow").lower(), _uri_value(params, "flow").lower())
    if flow not in FLOW_ALLOWED:
        return None
    security = _uri_value(params, "security", default="none").lower()
    if security not in ("tls", "reality", "none", "auto"):
        return None
    if flow and security not in ("tls", "reality"):
        return None
    return {
            "protocol": "vless",
            "uuid": uuid,
            "address": parsed.hostname,
            "port": port,
            "encryption": encryption,
            "type": net_type,
            "raw_type": raw_net_type,
            "security": security,
            "path": _uri_value(params, "path"), "host": _uri_value(params, "host"), "sni": _uri_value(params, "sni"),
            "fp": _uri_value(params, "fp"), "alpn": _uri_value(params, "alpn"), "serviceName": _uri_value(params, "serviceName"), "mode": _uri_value(params, "mode"),
            "pbk": pbk,
            "sid": sid,
            "flow": flow,
            "headerType": _uri_value(params, "headerType"), "spiderX": spx, "pqv": pqv, "pcs": pcs,
            "packet_encoding": _uri_value(params, "packetEncoding", "packet-encoding"), "ed": _uri_value(params, "ed"),
            "ech": _uri_value(params, "ech"), "fm": fm, "extra": extra, "vcn": _uri_value(params, "vcn"),
            "tag": urllib.parse.unquote(parsed.fragment).strip(), "diagnostics": [f"unknown query: {key}" for key in unknown]
        }
def parse_vmess(url):
    try:
        url = html.unescape(str(url).strip().replace("\ufeff", "").replace("\u200b", "").replace("\n", "").replace("\r", ""))
        if not url.startswith("vmess://"): return None

        if '@' in url:
            known = ("aid", "type", "security", "path", "host", "sni", "fp", "alpn", "serviceName", "encryption", "ech", "ed")
            uri = _uri_parts(url, ("vmess",), known)
            if not uri:
                return None
            parsed, params, unknown, userinfo, port = uri
            try:
                aid = int(_uri_value(params, "aid", default="0"))
            except (TypeError, ValueError):
                return None
            cipher = _uri_value(params, "encryption", default="auto").lower()
            if cipher not in ("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"):
                return None
            raw_net_type = re.sub(r"[^a-z0-9]", "", _uri_value(params, "type", default="tcp").lower()) or "tcp"
            net_type = "xhttp" if raw_net_type in ("http", "h2", "httpupgrade") else raw_net_type
            return {
                "protocol": "vmess",
                "uuid": urllib.parse.unquote(userinfo),
                "address": parsed.hostname,
                "port": port,
                "type": net_type,
                "raw_type": raw_net_type,
                "security": _uri_value(params, "security", default="none"),
                "path": _uri_value(params, "path"),
                "host": _uri_value(params, "host"),
                "sni": _uri_value(params, "sni"),
                "fp": _uri_value(params, "fp"),
                "alpn": _uri_value(params, "alpn"),
                "serviceName": _uri_value(params, "serviceName"),
                "aid": aid,
                "scy": cipher,
                "ech": _uri_value(params, "ech"),
                "ed": _uri_value(params, "ed"),
                "tag": urllib.parse.unquote(parsed.fragment).strip(),
                "diagnostics": [f"unknown query: {key}" for key in unknown],
            }

        content = url[8:]
        if '#' in content:
            b64, tag = content.rsplit('#', 1)
            tag = urllib.parse.unquote(tag).strip()
        else:
            b64 = content
            tag = "vmess"
            
        missing_padding = len(b64) % 4
        if missing_padding: b64 += '=' * (4 - missing_padding)
        
        try:
            decoded = base64.urlsafe_b64decode(b64).decode('utf-8', errors='ignore')
            data = json.loads(decoded)
            cipher = str(data.get("scy", "auto")).lower()
            if cipher not in ("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"):
                return None
            
            raw_net_type = str(data.get("net", "tcp")).lower()
            raw_net_type = re.sub(r"[^a-z0-9]", "", raw_net_type)
            if not raw_net_type:
                raw_net_type = "tcp"
            net_type = raw_net_type
            if net_type in ["http", "h2", "httpupgrade"]:
                net_type = "xhttp"
            
            return {
                "protocol": "vmess",
                "uuid": data.get("id"),
                "address": data.get("add"),
                "port": int(data.get("port", 0)),
                "aid": int(data.get("aid", 0)),
                "type": net_type,
                "raw_type": raw_net_type,
                "security": data.get("tls", "") if data.get("tls") else "none",
                "path": data.get("path", ""),
                "host": data.get("host", ""),
                "sni": data.get("sni", ""),
                "fp": data.get("fp", ""),
                "alpn": data.get("alpn", ""),
                "scy": cipher,
                "ech": data.get("ech", ""),
                "ed": str(data.get("ed", "")),
                "tag": data.get("ps", tag)
            }
        except:
            pass

        return None
    except Exception as e:
        safe_print(f"{Fore.RED}[VMESS ERROR] {e}{Style.RESET_ALL}")
        return None
    
def parse_trojan(url):
    uri = _uri_parts(url, ("trojan",), ("security", "sni", "peer", "type", "path", "host", "ech", "ed", "flow"))
    if not uri:
        return None
    parsed, params, unknown, userinfo, port = uri
    security = _uri_value(params, "security", default="tls").lower()
    if security not in ("tls", "reality"):
        return None
    return {
            "protocol": "trojan",
            "uuid": urllib.parse.unquote(userinfo),
            "address": parsed.hostname,
            "port": port, "security": security,
            "sni": _uri_value(params, "sni", "peer"), "type": _uri_value(params, "type", default="tcp"),
            "path": _uri_value(params, "path"), "host": _uri_value(params, "host"), "ech": _uri_value(params, "ech"),
            "ed": _uri_value(params, "ed"), "flow": _uri_value(params, "flow"), "tag": urllib.parse.unquote(parsed.fragment).strip(),
            "diagnostics": [f"unknown query: {key}" for key in unknown]
        }

def parse_ss(url):
    try:
        if '#' in url:
            url_clean, tag = url.split('#', 1)
        else:
            url_clean = url
            tag = "ss"
        
        parsed = urllib.parse.urlparse(url_clean)

        if '@' in url_clean:
            userinfo = urllib.parse.unquote(parsed.username or "")
            try:
                if userinfo and ':' not in userinfo:
                    missing_padding = len(userinfo) % 4
                    if missing_padding: userinfo += '=' * (4 - missing_padding)
                    decoded_info = base64.urlsafe_b64decode(userinfo).decode('utf-8')
                else:
                    decoded_info = userinfo
            except:
                decoded_info = userinfo
            
            if not decoded_info or ':' not in decoded_info: return None
            method, password = decoded_info.split(':', 1)
            address = parsed.hostname
            port = parsed.port
        else:
            b64 = url_clean.replace("ss://", "")
            missing_padding = len(b64) % 4
            if missing_padding: b64 += '=' * (4 - missing_padding)
            decoded = base64.urlsafe_b64decode(b64).decode('utf-8')
            if '@' not in decoded: return None
            method_pass, addr_port = decoded.rsplit('@', 1)
            method, password = method_pass.split(':', 1)
            address, port = addr_port.rsplit(':', 1)

        if not address or not port: return None
        
        method_lower = _normalize_ss_method(method)

        # Parse first, then validate against the Mihomo-safe set.
        if method_lower not in SS_MIHOMO_ALLOWED_METHODS:
            if GLOBAL_CFG.get("debug_mode"):
                safe_print(f"[yellow][DEBUG] Dropping SS link: unsupported cipher '{method}'[/]")
            return None

        return {
            "protocol": "shadowsocks",
            "address": address,
            "port": int(port),
            "method": method_lower,
            "password": password,
            "tag": urllib.parse.unquote(tag).strip()
        }
    except: return None

def parse_hysteria2(url):
    known = ("obfs", "obfs-password", "obfsPassword", "obfs-min-packet-size", "obfs-max-packet-size", "sni", "insecure", "pinSHA256", "ech", "alpn", "up", "down", "mport", "mportHopInt", "auth", "stun", "lport")
    uri = _uri_parts(url, ("hysteria2", "hy2", "hysteria2+realm", "hysteria2+realm+http"), known, repeat=("stun",))
    if not uri:
        return None
    parsed, params, unknown, userinfo, port = uri
    obfs = _uri_value(params, "obfs", default="none").lower()
    if obfs not in ("none", "salamander", "gecko") or _uri_value(params, "insecure", default="0") not in ("0", "1"):
        return None
    obfs_password = _uri_value(params, "obfs-password", "obfsPassword")
    if obfs != "none" and not obfs_password:
        return None
    gecko_min = _uri_value(params, "obfs-min-packet-size")
    gecko_max = _uri_value(params, "obfs-max-packet-size")
    if gecko_min or gecko_max:
        if obfs != "gecko" or not (gecko_min.isdigit() and gecko_max.isdigit()) or int(gecko_min) > int(gecko_max):
            return None
    lport = _uri_value(params, "lport")
    if lport and not is_valid_port(lport):
        return None
    realm = parsed.scheme.startswith("hysteria2+realm")
    if realm and (not _uri_value(params, "auth") or not parsed.path):
        return None
    return {
            "protocol": "hysteria2",
            "uuid": _uri_value(params, "auth") if realm else urllib.parse.unquote(userinfo),
            "address": parsed.hostname,
            "port": port, "sni": _uri_value(params, "sni"), "insecure": _uri_value(params, "insecure", default="0") == "1",
            "obfs": obfs, "obfs_password": obfs_password, "alpn": _uri_value(params, "alpn"),
            "fingerprint": _uri_value(params, "pinSHA256"), "ech": _uri_value(params, "ech"),
            "ports": _uri_value(params, "_authority_ports", "mport"), "hop_interval": _uri_value(params, "mportHopInt"),
            "up": _uri_value(params, "up"), "down": _uri_value(params, "down"),
            "obfs_min_packet_size": gecko_min, "obfs_max_packet_size": gecko_max,
            "realm": urllib.parse.unquote(parsed.path.lstrip("/")) if realm else "", "realm_http": parsed.scheme.endswith("+http"),
            "rendezvous": urllib.parse.unquote(userinfo) if realm else "", "stun": params.get("stun", []), "lport": _uri_value(params, "lport"),
            "tag": urllib.parse.unquote(parsed.fragment).strip(), "diagnostics": [f"unknown query: {key}" for key in unknown]
        }

def parse_anytls(url):
    uri = _uri_parts(url, ("anytls",), ("sni", "insecure", "hpkp", "ech", "udp", "security", "reality"))
    if not uri:
        return None
    parsed, params, unknown, userinfo, port = uri
    if (_uri_value(params, "insecure", default="0") not in ("0", "1")
            or _uri_value(params, "reality")
            or _uri_value(params, "security").lower() == "reality"):
        return None
    return {"protocol": "anytls", "uuid": urllib.parse.unquote(userinfo), "address": parsed.hostname, "port": port,
            "sni": _uri_value(params, "sni"), "insecure": _uri_value(params, "insecure", default="0") == "1",
            "fingerprint": _uri_value(params, "hpkp"), "ech": _uri_value(params, "ech"), "udp": _uri_value(params, "udp"),
            "tag": urllib.parse.unquote(parsed.fragment).strip(), "diagnostics": [f"unknown query: {key}" for key in unknown]}

def parse_tuic(url):
    uri = _uri_parts(url, ("tuic",), ("congestion_control", "alpn", "sni", "disable_sni", "udp_relay_mode"))
    if not uri:
        return None
    parsed, params, unknown, userinfo, port = uri
    userinfo = urllib.parse.unquote(userinfo)
    if not userinfo:
        return None
    if ":" in userinfo:
        uuid, password = userinfo.split(":", 1)
        version = 5
    else:
        uuid, password, version = userinfo, "", 4
    return {"protocol": "tuic", "uuid": uuid, "password": password, "version": version, "address": parsed.hostname, "port": port,
            "congestion_controller": _uri_value(params, "congestion_control"), "alpn": _uri_value(params, "alpn"),
            "sni": _uri_value(params, "sni"), "disable_sni": _uri_value(params, "disable_sni"), "udp_relay_mode": _uri_value(params, "udp_relay_mode"),
            "tag": urllib.parse.unquote(parsed.fragment).strip(), "diagnostics": [f"unknown query: {key}" for key in unknown]}

def _decode_urlsafe_text(value):
    try:
        value += "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value).decode("utf-8")
    except Exception:
        return ""

def parse_mihomo_auth_uri(url):
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("socks", "socks5", "socks5h", "http", "https") or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if not is_valid_port(port):
        return None
    native = {
        "type": "http" if scheme in ("http", "https") else "socks5",
        "server": parsed.hostname,
        "port": port,
        "skip-cert-verify": True,
        "_native_mihomo": True,
    }
    userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
    if userinfo:
        decoded = _decode_urlsafe_text(userinfo) or urllib.parse.unquote(userinfo)
        username, sep, password = decoded.partition(":")
        native["username"] = username
        native["password"] = password if sep else ""
    if scheme == "https":
        native["tls"] = True
    if parsed.fragment:
        native["name"] = urllib.parse.unquote(parsed.fragment)
    return native

def parse_hysteria1(url):
    known = ("peer", "obfs", "alpn", "auth", "protocol", "up", "down", "upmbps", "downmbps", "insecure")
    uri = _uri_parts(url, ("hysteria",), known)
    if not uri:
        return None
    parsed, params, unknown, _userinfo, port = uri
    if _uri_value(params, "insecure", default="0") not in ("0", "1", "true", "false"):
        return None
    up = _uri_value(params, "up", "upmbps")
    down = _uri_value(params, "down", "downmbps")
    if not up or not down:
        return None
    native = {
        "type": "hysteria",
        "server": parsed.hostname,
        "port": port,
        "sni": _uri_value(params, "peer"),
        "obfs": _uri_value(params, "obfs"),
        "auth_str": _uri_value(params, "auth"),
        "protocol": _uri_value(params, "protocol"),
        "up": up,
        "down": down,
        "skip-cert-verify": _uri_value(params, "insecure", default="0") in ("1", "true"),
        "_native_mihomo": True,
        "diagnostics": [f"unknown query: {key}" for key in unknown],
    }
    if _uri_value(params, "alpn"):
        native["alpn"] = [item for item in _uri_value(params, "alpn").split(",") if item]
    if parsed.fragment:
        native["name"] = urllib.parse.unquote(parsed.fragment)
    return native

def parse_ssr(url):
    decoded = _decode_urlsafe_text(url.split("://", 1)[-1])
    before, separator, query = decoded.partition("/?")
    parts = before.split(":")
    if not separator or len(parts) != 6 or not is_valid_port(parts[1]):
        return None
    host, port, protocol, method, obfs, password = parts
    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    native = {
        "type": "ssr", "server": host, "port": int(port), "protocol": protocol,
        "cipher": method, "obfs": obfs, "password": _decode_urlsafe_text(password),
        "udp": True, "_native_mihomo": True,
    }
    for source, target in (("obfsparam", "obfs-param"), ("protoparam", "protocol-param")):
        if params.get(source):
            native[target] = _decode_urlsafe_text(params[source][0])
    if params.get("remarks"):
        native["name"] = _decode_urlsafe_text(params["remarks"][0])
    return native

def parse_mierus_entries(url):
    known = ("port", "protocol", "profile", "multiplexing", "handshake-mode", "traffic-pattern")
    uri = _uri_parts(url, ("mierus",), known, repeat=("port", "protocol"))
    if not uri:
        return []
    parsed, params, unknown, userinfo, _port = uri
    ports, protocols = params.get("port", []), params.get("protocol", [])
    if not ports or len(ports) != len(protocols):
        return []
    username, separator, password = urllib.parse.unquote(userinfo).partition(":")
    base_name = urllib.parse.unquote(parsed.fragment) or _uri_value(params, "profile") or parsed.hostname
    entries = []
    for port, protocol in zip(ports, protocols):
        native = {
            "type": "mieru", "server": parsed.hostname, "transport": protocol,
            "udp": True, "username": username, "password": password if separator else "",
            "_native_mihomo": True, "diagnostics": [f"unknown query: {key}" for key in unknown],
            "name": f"{base_name}:{port}/{protocol}",
        }
        if "-" in port:
            start, separator, end = port.partition("-")
            if not separator or not (is_valid_port(start) and is_valid_port(end)) or int(start) > int(end):
                return []
            native["port-range"] = port
        elif is_valid_port(port):
            native["port"] = int(port)
        else:
            return []
        for key in ("multiplexing", "handshake-mode", "traffic-pattern"):
            if _uri_value(params, key):
                native[key] = _uri_value(params, key)
        entries.append(native)
    return entries

def parse_mierus(url):
    entries = parse_mierus_entries(url)
    if len(entries) == 1:
        return entries[0]
    if entries:
        return {"protocol": "unsupported", "diagnostics": ["multi-profile mierus URI must be expanded during content parsing"]}
    return None

def parse_proxy_url(proxy_url):
    try:
        if isinstance(proxy_url, dict) and proxy_url.get("_native_mihomo"):
            return proxy_url
        # Keep percent-encoded URI delimiters intact until component parsing.
        proxy_url = html.unescape(str(proxy_url).strip().replace("\ufeff", "").replace("\u200b", "").replace("\n", "").replace("\r", ""))
        if proxy_url.startswith("vless://"):
            return parse_vless(proxy_url)
        if proxy_url.startswith("vmess://"):
            return parse_vmess(proxy_url)
        if proxy_url.startswith("trojan://"):
            return parse_trojan(proxy_url)
        if proxy_url.startswith("ss://"):
            return parse_ss(proxy_url)
        if proxy_url.startswith(("hysteria2://", "hy2://", "hysteria2+realm://", "hysteria2+realm+http://")):
            return parse_hysteria2(proxy_url)
        if proxy_url.startswith("anytls://"):
            return parse_anytls(proxy_url)
        if proxy_url.startswith("tuic://"):
            return parse_tuic(proxy_url)
        if proxy_url.startswith(("socks://", "socks5://", "socks5h://", "http://", "https://")):
            return parse_mihomo_auth_uri(proxy_url)
        if proxy_url.startswith("hysteria://"):
            return parse_hysteria1(proxy_url)
        if proxy_url.startswith("ssr://"):
            return parse_ssr(proxy_url)
        if proxy_url.startswith("mierus://"):
            return parse_mierus(proxy_url)
    except Exception:
        return None
    return None

def canonical_proxy_key(proxy_url):
    # ponytail: canonical key on parsed dict (drops tag/fragment/query order),
    # fallback to fragment-stripped string for unsupported links
    try:
        if isinstance(proxy_url, dict):
            normalized = {k: v for k, v in proxy_url.items() if k not in ("name", "_native_mihomo", "_unsupported", "diagnostics")}
            return "native:" + json.dumps(normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        parsed = parse_proxy_url(proxy_url)
        if parsed:
            if parsed.get("protocol") == "unsupported":
                raise ValueError
            normalized = {k: v for k, v in parsed.items() if k not in ("tag", "diagnostics")}
            return "parsed:" + json.dumps(normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        pass
    try:
        import urllib.parse as _up
        parts = _up.urlsplit(proxy_url or "")
        return "fallback:" + _up.urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
    except Exception:
        return "fallback:" + str(proxy_url or "")

def _mihomo_network_opts(proxy_conf):
    raw_type = (proxy_conf.get("raw_type") or proxy_conf.get("type") or "tcp").lower()
    raw_type = re.sub(r"[^a-z0-9]", "", raw_type)
    if not raw_type:
        raw_type = "tcp"

    host = proxy_conf.get("host") or ""
    path = proxy_conf.get("path") or "/"
    hosts = [h.strip() for h in host.split(",") if h.strip()]

    if raw_type in ("tcp", "", "none"):
        return {}

    if raw_type in ("ws", "websocket"):
        ws_opts = {"path": path}
        if host:
            ws_opts["headers"] = {"Host": host}
        try:
            ed_int = int(proxy_conf.get("ed") or 0)
            if ed_int > 0:
                ws_opts["max-early-data"] = ed_int
        except (TypeError, ValueError):
            pass
        return {
            "network": "ws",
            "ws-opts": ws_opts
        }

    if raw_type in ("httpupgrade", "xhttp"):
        ws_opts = {
            "path": path,
            "v2ray-http-upgrade": True
        }
        if host:
            ws_opts["headers"] = {"Host": host}
        return {
            "network": "ws",
            "ws-opts": ws_opts
        }

    if raw_type == "h2":
        h2_opts = {"path": path}
        if hosts:
            h2_opts["host"] = hosts
        return {
            "network": "h2",
            "h2-opts": h2_opts
        }

    if raw_type == "http":
        http_opts = {
            "method": "GET",
            "path": [path]
        }
        if hosts:
            http_opts["headers"] = {"Host": hosts}
        return {
            "network": "http",
            "http-opts": http_opts
        }

    if raw_type in ("grpc", "gun"):
        service_name = proxy_conf.get("serviceName") or path.strip("/")
        grpc_opts = {}
        if service_name:
            grpc_opts["grpc-service-name"] = service_name
        data = {"network": "grpc"}
        if grpc_opts:
            data["grpc-opts"] = grpc_opts
        return data

    return None

def protocol_capability(proxy_url):
    """Single engine decision point for callers which can choose between cores."""
    proxy = parse_proxy_url(proxy_url)
    if not proxy:
        return "unsupported"
    if proxy.get("_native_mihomo"):
        return "unsupported" if proxy.get("_unsupported") or str(proxy.get("type", "")).lower() not in MIHOMO_NATIVE_TYPES else "mihomo"
    proto = proxy.get("protocol")
    if proto in ("anytls", "tuic"):
        return "mihomo"
    if proto == "hysteria2":
        return "unsupported" if proxy.get("realm") and proxy.get("lport") else ("mihomo" if proxy.get("realm") or proxy.get("insecure") or proxy.get("obfs") == "gecko" else "xray")
    if proto in ("vless", "vmess", "trojan", "shadowsocks"):
        if get_outbound_structure(proxy_url, "probe"):
            return "xray"
        return "mihomo" if get_mihomo_proxy_structure(proxy_url, "probe") else "unsupported"
    return "unsupported"

def mihomo_supports_shadowquic(core_path):
    """Reject an explicitly-versioned Mihomo older than ShadowQUIC support."""
    text = os.path.basename(str(core_path or ""))
    if core_path and os.path.exists(core_path):
        try:
            result = subprocess.run([core_path, "-v"], capture_output=True, text=True, timeout=3)
            text += result.stdout + result.stderr
        except Exception:
            pass
    match = re.search(r"v?(\d+)\.(\d+)\.(\d+)", text)
    return bool(match) and tuple(map(int, match.groups())) >= (1, 19, 29)

def get_mihomo_proxy_structure(proxy_url, name):
    proxy_conf = parse_proxy_url(proxy_url)
    if not proxy_conf:
        return None
    if proxy_conf.get("_native_mihomo"):
        if proxy_conf.get("_unsupported") or str(proxy_conf.get("type", "")).lower() not in MIHOMO_NATIVE_TYPES:
            return None
        native = {k: copy.deepcopy(v) for k, v in proxy_conf.items() if k not in ("_native_mihomo", "_unsupported", "diagnostics")}
        native["name"] = name
        if native.get("type") == "shadowquic" and not mihomo_supports_shadowquic(CORE_PATH):
            return None
        return native
    if not proxy_conf.get("address"):
        return None
    if not is_valid_port(proxy_conf.get("port")):
        return None

    proto = str(proxy_conf.get("protocol") or "").lower()
    if proto in ("vless", "vmess") and not is_valid_uuid(proxy_conf.get("uuid")):
        return None

    transport = _mihomo_network_opts(proxy_conf)
    if transport is None:
        return None

    base = {
        "name": name,
        "server": proxy_conf["address"],
        "port": int(proxy_conf["port"]),
        "udp": False
    }

    security = (proxy_conf.get("security") or "none").lower()
    sni = proxy_conf.get("sni") or proxy_conf.get("host") or ""

    if proto in ("ss", "shadowsocks"):
        method = _normalize_ss_method(proxy_conf.get("method"))
        if method not in SS_MIHOMO_ALLOWED_METHODS:
            if GLOBAL_CFG.get("debug_mode"):
                safe_print(f"[yellow][DEBUG] Skipping SS link for Mihomo: unsupported cipher '{method}'[/]")
            return None
        base.update({
            "type": "ss",
            "cipher": method,
            "password": proxy_conf.get("password", "")
        })
        return base

    if proto == "trojan":
        if not proxy_conf.get("uuid"):
            return None
        base.update({
            "type": "trojan",
            "password": proxy_conf["uuid"],
            "tls": True,
            "skip-cert-verify": False
        })
        if sni:
            base["servername"] = sni
        base.update(transport or {})
        return base

    if proto == "hysteria2":
        if not proxy_conf.get("uuid"):
            return None
        base.update({
            "type": "hysteria2",
            "password": proxy_conf["uuid"],
            "skip-cert-verify": bool(proxy_conf.get("insecure", False))
        })
        if proxy_conf.get("sni"):
            base["sni"] = proxy_conf["sni"]
        if proxy_conf.get("obfs") and proxy_conf.get("obfs") != "none":
            base["obfs"] = proxy_conf["obfs"]
            if proxy_conf.get("obfs_password"):
                base["obfs-password"] = proxy_conf["obfs_password"]
            if proxy_conf.get("obfs") == "gecko":
                for key, target in (("obfs_min_packet_size", "obfs-min-packet-size"), ("obfs_max_packet_size", "obfs-max-packet-size")):
                    if proxy_conf.get(key):
                        base[target] = int(proxy_conf[key])
        if proxy_conf.get("alpn"):
            base["alpn"] = [a.strip() for a in str(proxy_conf["alpn"]).split(",") if a.strip()]
        for key, target in (("fingerprint", "fingerprint"), ("ports", "ports"), ("hop_interval", "hop-interval"), ("up", "up"), ("down", "down")):
            if proxy_conf.get(key):
                base[target] = proxy_conf[key]
        if proxy_conf.get("ech"):
            base["ech-opts"] = {"enable": True, "config": proxy_conf["ech"]}
        if proxy_conf.get("realm"):
            if proxy_conf.get("lport"):
                return None  # Mihomo has no lport field; do not silently drop it.
            host = proxy_conf["address"]
            if ":" in host:
                host = f"[{host}]"
            scheme = "http" if proxy_conf.get("realm_http") else "https"
            base["realm-opts"] = {
                "enable": True,
                "server-url": f"{scheme}://{host}:{proxy_conf['port']}",
                "token": proxy_conf["rendezvous"],
                "realm-id": proxy_conf["realm"],
            }
            if proxy_conf.get("stun"):
                base["realm-opts"]["stun-servers"] = proxy_conf["stun"]
        return base

    if proto == "anytls":
        if not proxy_conf.get("uuid"):
            return None
        base.update({"type": "anytls", "password": proxy_conf["uuid"], "tls": True,
                     "skip-cert-verify": bool(proxy_conf.get("insecure", False))})
        if sni:
            base["sni"] = sni
        if proxy_conf.get("udp"):
            base["udp"] = _bool_value(proxy_conf["udp"])
        if proxy_conf.get("fingerprint"):
            base["fingerprint"] = proxy_conf["fingerprint"]
        if proxy_conf.get("ech"):
            base["ech-opts"] = {"enable": True, "config": proxy_conf["ech"]}
        return base

    if proto == "tuic":
        base.update({"type": "tuic", "udp-relay-mode": proxy_conf.get("udp_relay_mode") or "native"})
        if proxy_conf.get("version") == 4:
            base["token"] = proxy_conf["uuid"]
        else:
            base["uuid"] = proxy_conf["uuid"]
            base["password"] = proxy_conf["password"]
        if sni:
            base["sni"] = sni
        if proxy_conf.get("alpn"):
            base["alpn"] = [x.strip() for x in proxy_conf["alpn"].split(",") if x.strip()]
        if proxy_conf.get("congestion_controller"):
            base["congestion-controller"] = proxy_conf["congestion_controller"]
        if proxy_conf.get("disable_sni"):
            base["disable-sni"] = _bool_value(proxy_conf["disable_sni"])
        return base

    if proto == "vmess":
        base.update({
            "type": "vmess",
            "uuid": proxy_conf["uuid"],
            "alterId": int(proxy_conf.get("aid", 0)),
            "cipher": proxy_conf.get("scy") or "auto",
        })
    elif proto == "vless":
        base.update({
            "type": "vless",
            "uuid": proxy_conf["uuid"],
        })
        if proxy_conf.get("flow"):
            base["flow"] = proxy_conf["flow"]
        if proxy_conf.get("packet_encoding"):
            base["packet-encoding"] = proxy_conf["packet_encoding"]
        enc = (proxy_conf.get("encryption") or "none").strip()
        if enc and enc != "none":
            base["encryption"] = enc
    else:
        return None

    if security in ("tls", "reality", "xtls"):
        base["tls"] = True
        base["skip-cert-verify"] = False
        if sni:
            base["servername"] = sni
        fp = (proxy_conf.get("fp") or "").strip()
        base["client-fingerprint"] = fp if fp else "chrome"
        if proxy_conf.get("ech"):
            base["ech-opts"] = {"enable": True, "config": proxy_conf["ech"]}

    if security == "reality":
        pbk = proxy_conf.get("pbk", "").strip()
        if not pbk:
            return None
        reality_opts = {"public-key": pbk}
        sid = (proxy_conf.get("sid") or "").strip()
        if sid:
            reality_opts["short-id"] = sid
        base["reality-opts"] = reality_opts

    base.update(transport or {})
    return base

def get_proxy_tag(url):
    tag = "proxy"
    try:
        if isinstance(url, dict):
            return re.sub(r'[^\w\-\.]', '_', _first_scalar(url.get("name"), url.get("type", "proxy"))) or "proxy"
        url = clean_url(url)
        if '#' in url:
            _, raw_tag = url.rsplit('#', 1)
            tag = urllib.parse.unquote(raw_tag).strip()
        elif url.startswith("vmess"): 
            res = parse_vmess(url)
            if res: tag = res.get('tag', 'vmess')
    except: 
        pass
    
    tag = re.sub(r'[^\w\-\.]', '_', tag)
    return tag if tag else "proxy"

def is_valid_uuid(uuid_str):
    if not uuid_str: return False
    pattern = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    return bool(pattern.match(str(uuid_str)))

def is_valid_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except: return False
    
def get_outbound_structure(proxy_url, tag):
    try:
        proxy_conf = parse_proxy_url(proxy_url)
        if not proxy_conf or not proxy_conf.get("address") or not is_valid_port(proxy_conf.get("port")):
            return None
        proto = proxy_conf["protocol"]
        if proto in ("anytls", "tuic") or (proto == "hysteria2" and (proxy_conf.get("realm") or proxy_conf.get("insecure") or proxy_conf.get("obfs") == "gecko")):
            return None
        if proto in ("vless", "vmess") and not is_valid_uuid(proxy_conf.get("uuid")):
            return None
        if proto == "shadowsocks":
            method = _normalize_ss_method(proxy_conf.get("method"))
            if method not in SS_XRAY_ALLOWED_METHODS:
                return None
            return {"protocol": "shadowsocks", "tag": tag, "settings": {"address": proxy_conf["address"], "port": int(proxy_conf["port"]), "method": method, "password": proxy_conf["password"], "uot": False, "uotVersion": 0}}
        if proto == "hysteria2":
            if not proxy_conf.get("uuid"):
                return None
            tls = {"serverName": proxy_conf.get("sni") or proxy_conf["address"]}
            if proxy_conf.get("alpn"):
                tls["alpn"] = [x.strip() for x in proxy_conf["alpn"].split(",") if x.strip()]
            if proxy_conf.get("ech"):
                tls["echConfigList"] = proxy_conf["ech"]
            settings = {"version": 2, "address": proxy_conf["address"], "port": int(proxy_conf["port"])}
            hysteria = {"version": 2, "auth": proxy_conf["uuid"]}
            stream = {"network": "hysteria", "security": "tls", "tlsSettings": tls, "hysteriaSettings": hysteria}
            finalmask = {}
            if proxy_conf.get("obfs") == "salamander":
                finalmask["udp"] = [{"type": "salamander", "settings": {"password": proxy_conf.get("obfs_password", "")}}]
            quic = {}
            if proxy_conf.get("ports"):
                quic["udpHop"] = {"ports": proxy_conf["ports"], "interval": proxy_conf.get("hop_interval") or 30}
            if proxy_conf.get("up"):
                quic["brutalUp"] = proxy_conf["up"]
            if proxy_conf.get("down"):
                quic["brutalDown"] = proxy_conf["down"]
            if quic:
                finalmask["quicParams"] = quic
            if finalmask:
                stream["finalmask"] = finalmask
            return {"protocol": "hysteria", "tag": tag, "settings": settings, "streamSettings": stream}
        security = (proxy_conf.get("security") or "none").lower()
        network = proxy_conf.get("type") or "raw"
        network = {
            "tcp": "raw", "splithttp": "xhttp", "mkcp": "kcp",
            "websocket": "ws", "gun": "grpc",
        }.get(network, network)
        if network in ("http", "h2", "h3", "quic") or (security == "reality" and network not in ("raw", "xhttp", "grpc")):
            return None
        stream = {"network": network, "security": "none" if security == "auto" else security}
        tls = {"serverName": proxy_conf.get("sni") or proxy_conf.get("host") or proxy_conf["address"], "fingerprint": proxy_conf.get("fp") or "chrome"}
        if proxy_conf.get("alpn"):
            tls["alpn"] = [x.strip() for x in proxy_conf["alpn"].split(",") if x.strip()]
        if proxy_conf.get("pcs"):
            tls["pinnedPeerCertSha256"] = proxy_conf["pcs"].split(",")
        if proxy_conf.get("vcn"):
            tls["verifyPeerCertByName"] = proxy_conf["vcn"]
        if security == "tls":
            if proxy_conf.get("ech"): tls["echConfigList"] = proxy_conf["ech"]
            stream["tlsSettings"] = tls
        elif security == "reality":
            if not proxy_conf.get("pbk"): return None
            reality = {"password": proxy_conf["pbk"], "shortId": proxy_conf.get("sid", ""), "serverName": tls["serverName"], "fingerprint": tls["fingerprint"], "spiderX": proxy_conf.get("spiderX") or "/"}
            if proxy_conf.get("pqv"): reality["mldsa65Verify"] = proxy_conf["pqv"]
            stream["realitySettings"] = reality
        if network == "xhttp":
            stream["xhttpSettings"] = {"path": proxy_conf.get("path") or "/", "host": proxy_conf.get("host") or "", "mode": proxy_conf.get("mode") or "auto"}
            if proxy_conf.get("extra") is not None: stream["xhttpSettings"]["extra"] = proxy_conf["extra"]
        elif network == "grpc":
            stream["grpcSettings"] = {"serviceName": proxy_conf.get("serviceName") or (proxy_conf.get("path") or "/").strip("/")}
        elif network in ("ws", "httpupgrade"):
            key = "httpupgradeSettings" if network == "httpupgrade" else "wsSettings"
            stream[key] = {"path": proxy_conf.get("path") or "/", "host": proxy_conf.get("host") or ""}
        elif network == "kcp":
            if proxy_conf.get("headerType") not in ("", "none") and proxy_conf.get("fm") is None:
                return None
        if proxy_conf.get("fm") is not None: stream["finalmask"] = proxy_conf["fm"]
        base = {"address": proxy_conf["address"], "port": int(proxy_conf["port"]), "level": 0}
        if proto == "vless":
            base.update({"id": proxy_conf["uuid"], "encryption": proxy_conf.get("encryption") or "none", "flow": proxy_conf.get("flow") or ""})
        elif proto == "vmess":
            base.update({"id": proxy_conf["uuid"], "security": proxy_conf.get("scy") or "auto", "experiments": ""})
        elif proto == "trojan":
            base.update({"password": proxy_conf.get("uuid"), "flow": proxy_conf.get("flow") or ""})
        else:
            return None
        return {"protocol": proto, "tag": tag, "settings": base, "streamSettings": stream}
    except Exception:
        return None

def create_batch_config_file(proxy_list, start_port, work_dir):
    inbounds = []
    outbounds = []
    rules = []
    valid_proxies = []
    
    for i, url in enumerate(proxy_list):
        port = start_port + i
        in_tag = f"in_{port}"
        out_tag = f"out_{port}"
        
        out_struct = get_outbound_structure(url, out_tag)
        if not out_struct: 
            continue
        
        if "streamSettings" in out_struct:
            ss = out_struct["streamSettings"]
            net = ss.get("network", "")
            
            if net == "xhttp":
                ss.pop("wsSettings", None)
                ss.pop("grpcSettings", None)
                ss.pop("httpSettings", None)
                ss.pop("h2Settings", None)
                ss.pop("httpupgradeSettings", None)
        
        inbounds.append({
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "tag": in_tag,
            "settings": {"udp": False}
        })
        
        outbounds.append(out_struct)
        rules.append({
            "type": "field",
            "inboundTag": [in_tag],
            "outboundTag": out_tag
        })
        valid_proxies.append((url, port))
    
    if not outbounds:
        return None, None, "No valid proxies"
    
    full_config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules
        }
    }
    
    config_path = os.path.join(work_dir, f"batch_{start_port}.json")
    with open(config_path, 'w') as f:
        json.dump(full_config, f, indent=2)
    
    return config_path, valid_proxies, None

def create_mihomo_config_file(proxy_url, local_port, work_dir):
    proxy_name = f"out_{local_port}"
    proxy_struct = get_mihomo_proxy_structure(proxy_url, proxy_name)
    if not proxy_struct:
        return None, None, "No valid proxy for mihomo"

    full_config = {
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "silent",
        "ipv6": True,
        "socks-port": local_port,
        "proxies": [proxy_struct],
        "proxy-groups": [
            {
                "name": "MK_CHECK",
                "type": "select",
                "proxies": [proxy_name]
            }
        ],
        "rules": ["MATCH,MK_CHECK"]
    }

    config_path = os.path.join(work_dir, f"batch_{local_port}_mihomo.json")
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(full_config, f, indent=2, ensure_ascii=False)

    return config_path, [(proxy_url, local_port)], None

def save_failed_batch(config_path, error_output, exit_code):
    try:
        failed_dir = os.path.join(os.getcwd(), "failed_batches")
        os.makedirs(failed_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.basename(config_path).replace(".json", "")
        
        dest_json = os.path.join(failed_dir, f"{base_name}_{timestamp}.json")
        shutil.copy2(config_path, dest_json)
        
        log_path = os.path.join(failed_dir, f"{base_name}_{timestamp}.log.txt")
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"Exit code: {exit_code}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Config: {config_path}\n")
            f.write("-" * 50 + "\n")
            f.write(error_output or "No output captured")
        
        safe_print(f"[yellow]📁 Debug files saved to: {failed_dir}[/]")
        if CORE_FLAVOR == "mihomo":
            safe_print(f"[dim]   Reproduce: \"{CORE_PATH}\" -f \"{dest_json}\"[/]")
        else:
            safe_print(f"[dim]   Reproduce: \"{CORE_PATH}\" run -test -c \"{dest_json}\"[/]")
        
        return dest_json, log_path
    except Exception as e:
        safe_print(f"[red]Failed to save debug artifacts: {e}[/]")
        return None, None

def run_core(core_path, config_path):
    if platform.system() != "Windows":
        try:
            st = os.stat(core_path)
            os.chmod(core_path, st.st_mode | stat.S_IXEXEC)
        except Exception as e:
            pass
    if CORE_FLAVOR == "mihomo":
        cmd = [core_path, "-f", config_path]
    elif "xray" in core_path.lower():
        cmd = [core_path, "run", "-c", config_path]
    else:
        cmd = [core_path, "-c", config_path]
    startupinfo = None
    if OS_SYSTEM == "windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            startupinfo=startupinfo,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
    except Exception as e:
        safe_print(f"[bold red]Core launch error: {e}[/]")
        return None

def kill_core(proc):
    if not proc:
        return
    
    try:
        if psutil.pid_exists(proc.pid):
            parent = psutil.Process(proc.pid)
            # УБИВАЕМ ДЕТЕЙ
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except:
                    pass
            parent.kill()
        else:
            if OS_SYSTEM == "windows":
                subprocess.run(["taskkill", "/F", "/PID", str(proc.pid)], 
                             capture_output=True)
    except:
        pass
    
    try:
        proc.terminate()
        proc.wait(timeout=1.0)
    except:
        try:
            proc.kill()
        except:
            pass

# ponytail: regex + drop helper for Xray batch auto-repair.
# Tag scheme stays out_{port} so we can map it back to valid_mapping.
_BAD_OUTBOUND_TAG_RE = re.compile(
    r'failed to build outbound config with tag\s*[:=]?\s*["\']?(out_\d+)',
    re.IGNORECASE,
)

def extract_bad_outbound_tag(log_text):
    """Return the offending outbound tag (e.g. 'out_10000') from a core log, or None."""
    if not log_text:
        return None
    m = _BAD_OUTBOUND_TAG_RE.search(log_text)
    return m.group(1) if m else None

def drop_proxy_by_outbound_tag(active_proxy_list, valid_mapping, out_tag):
    """Drop the proxy whose mapped port matches `out_tag`.

    Returns (new_list, dropped_url) without mutating `active_proxy_list`.
    `dropped_url` is None when the tag maps to nothing (unrecognized/bad).
    """
    if not out_tag:
        return list(active_proxy_list), None
    try:
        target_port = int(out_tag.split("_", 1)[1])
    except (IndexError, ValueError):
        return list(active_proxy_list), None
    dropped_url = None
    for url, port in valid_mapping or []:
        if port == target_port:
            dropped_url = url
            break
    if dropped_url is None:
        return list(active_proxy_list), None
    new_list, removed = [], False
    for item in active_proxy_list:
        if not removed and item == dropped_url:
            removed = True
            continue
        new_list.append(item)
    return new_list, dropped_url

def check_connection(local_port, domain, timeout):
    proxies = {
        'http': f'socks5://127.0.0.1:{local_port}',
        'https': f'socks5://127.0.0.1:{local_port}'
    }
    try:
        start = time.time()
        resp = requests.get(domain, proxies=proxies, timeout=timeout, verify=False)
        end = time.time()
        if resp.status_code < 400:
            return round((end - start) * 1000), None
        else:
            return False, f"HTTP {resp.status_code}"
    except (BadStatusLine, RemoteDisconnected):
        return False, "Handshake Fail"
    except Exception as e:
        return False, str(e)
    
def check_speed_download(local_port, url_file, timeout=10, conn_timeout=5, max_mb=5, min_kb=1):
    targets = GLOBAL_CFG.get("speed_targets", [])
    
    pool = [url_file] + targets if url_file else list(targets)
    if not url_file: random.shuffle(pool)
    
    pool = [u for u in pool if u]
    if not pool: return 0.0

    proxies = {
        'http': f'socks5://127.0.0.1:{local_port}',
        'https': f'socks5://127.0.0.1:{local_port}'
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Connection": "keep-alive"
    }

    limit_bytes = max_mb * 1024 * 1024
    
    for target_url in pool:
        try:
            with requests.get(target_url, proxies=proxies, headers=headers, stream=True, 
                              timeout=(conn_timeout, timeout), verify=False) as r:
                
                if r.status_code >= 400:
                    continue

                start_time = time.time()
                total_bytes = 0
                
                for chunk in r.iter_content(chunk_size=32768):
                    if chunk:
                        total_bytes += len(chunk)
                    
                    curr_time = time.time()
                    if (curr_time - start_time) > timeout or total_bytes >= limit_bytes:
                        break
                
                duration = time.time() - start_time
                if duration <= 0.1: duration = 0.1

                if total_bytes < (min_kb * 1024):
                    if duration > (timeout * 0.8):
                        return 0.0
                    continue

                speed_bps = total_bytes / duration
                speed_mbps = speed_bps / 125000
                
                return round(speed_mbps, 2)

        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            continue
        except Exception:
            pass

    return 0.0

def Checker_xray(proxyList, localPortStart, testDomain, timeOut, t2exec, t2kill, 
                 checkSpeed=False, speedUrl="", sortBy="ping", speedCfg=None, 
                 speedSemaphore=None, maxInternalThreads=50, max_ping_ms=0,
                 progress=None, task_id=None):
    
    current_live_results = []
    if speedCfg is None: speedCfg = {}

    # Working copy so the caller's proxyList is never mutated by batch repair.
    active_proxy_list = list(proxyList)
    proc = None
    configPath = None
    valid_mapping = []
    core_started = False

    # Retry loop: rebuild+relaunch the batch, dropping one bad outbound per
    # recognized failure, until the core starts, the list is empty, or the
    # error is unrecognized.
    while active_proxy_list:
        configPath, valid_mapping, err = create_batch_config_file(
            active_proxy_list, localPortStart, TEMP_DIR
        )
        if err or not valid_mapping:
            return current_live_results

        proc = run_core(CORE_PATH, configPath)
        if not proc:
            safe_print(f"[bold red][BATCH ERROR] Не удалось создать процесс ядра![/]")
            return current_live_results

        # Post-start probe: detect early exit (with exit/error msg) vs port open.
        core_started = False
        error_msg = ""
        exitcode = None
        start_time = time.time()
        max_wait = max(t2exec, 5.0)
        while (time.time() - start_time) < max_wait:
            poll_result = proc.poll()
            if poll_result is not None:
                exitcode = proc.returncode
                if exitcode == 0:
                    break
                try:
                    out_data, _ = proc.communicate(timeout=1)
                    if out_data:
                        error_msg = out_data.strip()[-2000:]
                except Exception as e:
                    error_msg = f"Failed to read error output: {e}"
                break
            if is_port_in_use(valid_mapping[0][1]):
                core_started = True
                break
            time.sleep(0.1)

        if core_started:
            time.sleep(0.3)
            break

        # Did not start: preserve old stdout fallback before killing.
        if exitcode is None:
            exitcode = proc.poll()
            error_msg = "Unknown error"
            try:
                if proc.stdout:
                    err_lines = []
                    for line in proc.stdout:
                        err_lines.append(line.strip())
                        if len(err_lines) > 50:
                            break
                    if err_lines:
                        error_msg = "\n".join(err_lines[-20:])
            except Exception:
                try:
                    proc.wait(timeout=0.5)
                    error_msg = "Core failed silently"
                except Exception:
                    error_msg = "Core timeout"

        kill_core(proc)
        proc = None

        bad_tag = extract_bad_outbound_tag(error_msg)
        if bad_tag:
            new_list, dropped = drop_proxy_by_outbound_tag(
                active_proxy_list, valid_mapping, bad_tag
            )
            if dropped is not None:
                safe_print(
                    f"[yellow][BATCH REPAIR][/] отбрасываю битый outbound "
                    f"{bad_tag} ({dropped})"
                )
                if progress and task_id is not None:
                    progress.advance(task_id, 1)
                try:
                    if configPath and os.path.exists(configPath):
                        os.remove(configPath)
                except Exception:
                    pass
                active_proxy_list = new_list
                continue

        # Unrecognized failure: save the failed batch (old debug behavior).
        safe_print(f"[bold red]BATCH FAILED[/] [yellow]Ядро не запустилось (Exit: {exitcode})[/]")
        safe_print(f"[dim]Error: {error_msg[:300]}[/]")
        save_failed_batch(configPath, error_msg, exitcode if exitcode is not None else 0)
        try:
            if configPath and os.path.exists(configPath):
                os.remove(configPath)
        except Exception:
            pass
        return current_live_results

    # Loop exited because active_proxy_list is empty: nothing left to check.
    if not active_proxy_list:
        return current_live_results
    
    def check_single_port(item):
        if CTRL_C: return None
        target_url, target_port = item
        
        proxy_speed = 0.0
        conf = parse_proxy_url(target_url)
        
        addr_info = f"{conf['address']}:{conf['port']}" if conf else "unknown"
        proxy_tag = get_proxy_tag(target_url)
        
        ping_res, error_reason = check_connection(target_port, testDomain, timeOut)
        
        if ping_res:
            if max_ping_ms and ping_res > max_ping_ms:
                safe_print(f"[yellow][DROP][/] [white]{addr_info:<25}[/] | {ping_res:>4}ms > {max_ping_ms}ms | {proxy_tag}")
                if progress and task_id is not None:
                    progress.advance(task_id, 1)
                return None

            if checkSpeed:
                with (speedSemaphore if speedSemaphore else Lock()):
                    proxy_speed = check_speed_download(target_port, speedUrl, **speedCfg)
                    if proxy_speed is None:
                        proxy_speed = 0.0
                sp_color = "green" if proxy_speed > 15 else "yellow" if proxy_speed > 5 else "red"
                safe_print(f"[green][LIVE][/] [white]{addr_info:<25}[/] | {ping_res:>4}ms | [{sp_color}]{proxy_speed:>5} Mbps[/] | {proxy_tag}")
            else:
                safe_print(f"[green][LIVE][/] [white]{addr_info:<25}[/] | {ping_res:>4}ms | {proxy_tag}")
            
            if progress and task_id is not None:
                progress.advance(task_id, 1)
            return (target_url, ping_res, proxy_speed)
        
        else:
            if progress and task_id is not None:
                progress.advance(task_id, 1)
            return None

    max_workers = min(len(valid_mapping), maxInternalThreads)
    with ThreadPoolExecutor(max_workers=max_workers) as inner_exec:
        raw_results = list(inner_exec.map(check_single_port, valid_mapping))
    
    current_live_results = [r for r in raw_results if r is not None]

    kill_core(proc)
    time.sleep(t2kill)
    try:
        if os.path.exists(configPath):
            os.remove(configPath)
    except: pass
    
    return current_live_results

def Checker_mihomo(proxyList, localPortStart, testDomain, timeOut, t2exec, t2kill,
                   checkSpeed=False, speedUrl="", sortBy="ping", speedCfg=None,
                   speedSemaphore=None, maxInternalThreads=50, max_ping_ms=0,
                   progress=None, task_id=None):
    current_live_results = []
    if speedCfg is None:
        speedCfg = {}

    for idx, target_url in enumerate(proxyList):
        if CTRL_C:
            break

        target_port = localPortStart + idx
        configPath, valid_mapping, err = create_mihomo_config_file(target_url, target_port, TEMP_DIR)
        if err or not valid_mapping:
            if progress and task_id is not None:
                progress.advance(task_id, 1)
            continue

        proc = run_core(CORE_PATH, configPath)
        if not proc:
            try:
                if os.path.exists(configPath):
                    os.remove(configPath)
            except Exception:
                pass
            if progress and task_id is not None:
                progress.advance(task_id, 1)
            continue

        core_started = wait_for_core_start(target_port, max(t2exec, 4.0))
        if core_started:
            # Для mihomo нужен небольшой прогрев после открытия socks-порта,
            # иначе при высоком параллелизме часто ловим transient 10053/EOF.
            time.sleep(1.0)

        if not core_started:
            exitcode = proc.poll()
            error_msg = "Core timeout"
            try:
                if proc.stdout:
                    err_lines = []
                    for line in proc.stdout:
                        err_lines.append(line.strip())
                        if len(err_lines) > 30:
                            break
                    if err_lines:
                        error_msg = "\n".join(err_lines[-15:])
            except Exception:
                pass
            safe_print(f"[bold red]BATCH FAILED[/] [yellow]Ядро не запустилось (Exit: {exitcode})[/]")
            safe_print(f"[dim]Error: {error_msg[:300]}[/]")
            save_failed_batch(configPath, error_msg, exitcode)
            kill_core(proc)
            try:
                if os.path.exists(configPath):
                    os.remove(configPath)
            except Exception:
                pass
            if progress and task_id is not None:
                progress.advance(task_id, 1)
            continue

        conf = parse_proxy_url(target_url)
        addr_info = f"{(conf.get('address') or conf.get('server', 'unknown'))}:{conf.get('port', '')}" if conf else "unknown"
        proxy_tag = get_proxy_tag(target_url)

        proxy_speed = 0.0
        ping_res, error_reason = check_connection(target_port, testDomain, timeOut)
        if not ping_res and error_reason:
            low_err = str(error_reason).lower()
            if ("connection aborted" in low_err) or ("ssleoferror" in low_err) or ("eof" in low_err):
                time.sleep(0.35)
                ping_res, error_reason = check_connection(target_port, testDomain, timeOut)

        if ping_res:
            if max_ping_ms and ping_res > max_ping_ms:
                safe_print(f"[yellow][DROP][/] [white]{addr_info:<25}[/] | {ping_res:>4}ms > {max_ping_ms}ms | {proxy_tag}")
            else:
                if checkSpeed:
                    with (speedSemaphore if speedSemaphore else Lock()):
                        proxy_speed = check_speed_download(target_port, speedUrl, **speedCfg)
                        if proxy_speed is None:
                            proxy_speed = 0.0
                    sp_color = "green" if proxy_speed > 15 else "yellow" if proxy_speed > 5 else "red"
                    safe_print(f"[green][LIVE][/] [white]{addr_info:<25}[/] | {ping_res:>4}ms | [{sp_color}]{proxy_speed:>5} Mbps[/] | {proxy_tag}")
                else:
                    safe_print(f"[green][LIVE][/] [white]{addr_info:<25}[/] | {ping_res:>4}ms | {proxy_tag}")
                current_live_results.append((target_url, ping_res, proxy_speed))

        kill_core(proc)
        time.sleep(t2kill)
        try:
            if os.path.exists(configPath):
                os.remove(configPath)
        except Exception:
            pass

        if progress and task_id is not None:
            progress.advance(task_id, 1)

    return current_live_results

def Checker(proxyList, localPortStart, testDomain, timeOut, t2exec, t2kill,
            checkSpeed=False, speedUrl="", sortBy="ping", speedCfg=None,
            speedSemaphore=None, maxInternalThreads=50, max_ping_ms=0,
            progress=None, task_id=None):
    if CORE_FLAVOR == "mihomo":
        return Checker_mihomo(
            proxyList, localPortStart, testDomain, timeOut, t2exec, t2kill,
            checkSpeed, speedUrl, sortBy, speedCfg, speedSemaphore, maxInternalThreads, max_ping_ms,
            progress, task_id
        )
    return Checker_xray(
        proxyList, localPortStart, testDomain, timeOut, t2exec, t2kill,
        checkSpeed, speedUrl, sortBy, speedCfg, speedSemaphore, maxInternalThreads, max_ping_ms,
        progress, task_id
    )


def _arg_was_provided(*flags):
    argv = sys.argv[1:]
    for flag in flags:
        if flag in argv:
            return True
        prefix = f"{flag}="
        if any(arg.startswith(prefix) for arg in argv):
            return True
    return False


def apply_mtproto_arg_defaults(args):
    if not (getattr(args, "mtproto", False) or getattr(args, "mtproto_login", False)):
        return args

    mt_cfg = get_mtproto_config(GLOBAL_CFG)
    mtproto_speed_requested = False
    if _arg_was_provided("--speed"):
        mtproto_speed_requested = True
    elif _arg_was_provided("--sort") and str(getattr(args, "sort_by", "ping")).strip().lower() == "speed":
        mtproto_speed_requested = True

    args.mtproto_speed_flag_used = mtproto_speed_requested

    if not _arg_was_provided("-o", "--output"):
        args.output = mt_cfg.get("output_file", "sortedMtproto.txt")
    if not _arg_was_provided("-T", "--threads"):
        args.threads = int(mt_cfg.get("threads", 20) or 20)
    if not _arg_was_provided("-t", "--timeout"):
        args.timeout = int(mt_cfg.get("timeout", 5) or 5)
    if not _arg_was_provided("--max-ping"):
        args.max_ping = int(mt_cfg.get("max_ping_ms", 0) or 0)

    args.sort_by = "ping"
    args.speed_check = False
    return args


def _derive_mtproto_sidecar_path(output_file, suffix=".conn.txt"):
    output_file = str(output_file or "sortedMtproto.txt")
    root, ext = os.path.splitext(output_file)
    if ext:
        return f"{root}{suffix}"
    return f"{output_file}{suffix}"


def _build_mtproto_promo_lookup(all_results):
    promo_by_proxy = {}
    for result in all_results or []:
        if not isinstance(result, dict):
            continue
        entry = result.get("entry")
        if not isinstance(entry, dict):
            continue
        proxy_url = entry.get("canonical_url") or entry.get("original_url")
        if proxy_url:
            promo_by_proxy[proxy_url] = result.get("promo_data")
    return promo_by_proxy


def _format_mtproto_promo_summary(summary):
    if not isinstance(summary, dict):
        return ""
    unknown = int(summary.get("unknown") or 0)
    unknown_suffix = f", UNKNOWN: {unknown}" if unknown else ""
    return (
        f"PROMO: {int(summary.get('present') or 0)} found, "
        f"{int(summary.get('empty') or 0)} empty, "
        f"{int(summary.get('error') or 0)} errors, "
        f"{int(summary.get('unsupported') or 0)} unsupported, "
        f"{int(summary.get('auth_required') or 0)} auth required"
        f", {int(summary.get('skipped') or 0)} skipped"
        f"{unknown_suffix}"
    )


def _build_mtproto_login_callbacks():
    phone_value = Prompt.ask("[cyan][?][/] Телефон Telegram в международном формате")

    def code_callback():
        return Prompt.ask("[cyan][?][/] Код Telegram")

    def password_callback():
        return Prompt.ask("[cyan][?][/] Пароль 2FA Telegram", password=True)

    return phone_value, code_callback, password_callback


def _decorate_mtproto_promo_logs(log_lines, all_results):
    decorated = []
    for index, log_line in enumerate(log_lines or []):
        line = str(log_line)
        result = all_results[index] if index < len(all_results or []) else None
        if isinstance(result, dict) and result.get("status") == "live" and " | Promo:" not in line:
            promo_label = mtproto_checker.format_promo_display(result.get("promo_data")) or "unknown"
            line = f"{line} | Promo: {promo_label}"
        decorated.append(line)
    return decorated


def build_mtproto_runtime_cfg(args):
    runtime_cfg = get_mtproto_config(GLOBAL_CFG)
    runtime_cfg["threads"] = max(1, int(getattr(args, "threads", runtime_cfg.get("threads", 20)) or 1))
    runtime_cfg["timeout"] = max(1, int(getattr(args, "timeout", runtime_cfg.get("timeout", 5)) or 1))
    runtime_cfg["max_ping_ms"] = max(0, int(getattr(args, "max_ping", runtime_cfg.get("max_ping_ms", 0)) or 0))
    runtime_cfg["dc_probe_limit"] = max(1, int(runtime_cfg.get("dc_probe_limit", 3) or 3))
    runtime_cfg["probe_policy"] = str(runtime_cfg.get("probe_policy", "balanced") or "balanced").strip().lower()
    runtime_cfg["connect_retries"] = max(0, min(3, int(runtime_cfg.get("connect_retries", 1) or 0)))
    runtime_cfg["rpc_retries"] = max(0, min(3, int(runtime_cfg.get("rpc_retries", 1) or 0)))
    runtime_cfg["fetch_promo_data"] = _bool_value(runtime_cfg.get("fetch_promo_data", True), True)
    runtime_cfg["promo_session_file"] = str(runtime_cfg.get("promo_session_file") or "mtproto_promo")
    runtime_cfg["promo_threads"] = max(
        1,
        min(8, int(runtime_cfg.get("promo_threads", runtime_cfg.get("promo_parallelism", 3)) or 1)),
    )
    runtime_cfg["promo_parallelism"] = runtime_cfg["promo_threads"]
    runtime_cfg["promo_timeout"] = max(1, int(runtime_cfg.get("promo_timeout", min(runtime_cfg["timeout"], 6)) or 1))
    runtime_cfg["promo_probe_limit"] = max(
        0,
        int(runtime_cfg.get("promo_probe_limit", runtime_cfg.get("promo_limit", 0)) or 0),
    )
    runtime_cfg["promo_limit"] = runtime_cfg["promo_probe_limit"]
    runtime_cfg["save_connect_only"] = _bool_value(runtime_cfg.get("save_connect_only", True), True)
    runtime_cfg["debug_attempts"] = _bool_value(runtime_cfg.get("debug_attempts", False), False)
    runtime_cfg["crypto_backend"] = str(
        getattr(args, "mtproto_crypto", runtime_cfg.get("crypto_backend", "auto"))
        or runtime_cfg.get("crypto_backend", "auto")
    ).strip().lower()
    runtime_cfg["output_file"] = str(getattr(args, "output", runtime_cfg.get("output_file", "sortedMtproto.txt")) or runtime_cfg.get("output_file", "sortedMtproto.txt"))
    runtime_cfg["connect_only_output_file"] = str(
        runtime_cfg.get("connect_only_output_file")
        or _derive_mtproto_sidecar_path(runtime_cfg["output_file"])
    )
    runtime_cfg["attempts_output_file"] = str(
        runtime_cfg.get("attempts_output_file")
        or _derive_mtproto_sidecar_path(runtime_cfg["output_file"], ".attempts.json")
    )
    runtime_cfg["promo_output_file"] = str(
        runtime_cfg.get("promo_output_file")
        or _derive_mtproto_sidecar_path(runtime_cfg["output_file"], ".promo.json")
    )
    return runtime_cfg


def _merge_mtproto_entries(target_map, entries):
    before = len(target_map)
    for entry in entries:
        if not entry:
            continue
        target_map.setdefault(entry["unique_key"], entry)
    return len(target_map) - before


def run_mtproto_logic(args):
    if not MTPROTO_AVAILABLE or mtproto_checker is None:
        safe_print("[bold red]MTProto checker module не найден.[/]")
        return

    runtime_cfg = build_mtproto_runtime_cfg(args)
    if not _bool_value(runtime_cfg.get("enabled", True), True):
        safe_print("[yellow]MTProto checker отключён в config.json (mtproto.enabled = false)[/]")
        return

    if getattr(args, "mtproto_speed_flag_used", False):
        safe_print("[yellow]Telegram proxy mode: speed test и sort=speed не поддерживаются, используется сортировка только по ping[/]")

    ok, err = mtproto_checker.validate_runtime_config(runtime_cfg)
    if not ok:
        safe_print(f"[bold red]MTProto config error:[/] {err}")
        return

    entries_map = {}

    if args.file:
        fpath = args.file.strip('"')
        if os.path.exists(fpath):
            safe_print(f"[cyan]>> Чтение Telegram proxy файла: {fpath}[/]")
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                file_payload = f.read()
            parsed_entries, mtproto_hits, socks_hits, invalid_count, proxy_like_hits = mtproto_checker.parse_mtproto_content(file_payload)
            added_unique = _merge_mtproto_entries(entries_map, parsed_entries)
            safe_print(
                f"[dim]>> Telegram proxy-ссылок в файле: {proxy_like_hits}, "
                f"MTProto: {mtproto_hits}, SOCKS: {socks_hits}, "
                f"invalid: {invalid_count}, добавлено уникальных: {added_unique}[/]"
            )
        else:
            safe_print(f"[bold red]Файл не найден: {fpath}[/]")
            return

    if args.url:
        raw_url = args.url.strip()
        if mtproto_checker.is_telegram_proxy_link(raw_url):
            parsed_entry, parse_error = mtproto_checker.parse_mtproto_url(raw_url)
            if not parsed_entry:
                safe_print(f"[bold red]Некорректная Telegram proxy ссылка:[/] {parse_error}")
                return
            added_unique = _merge_mtproto_entries(entries_map, [parsed_entry])
            safe_print(f"[dim]>> Прямая Telegram proxy ссылка добавлена: {added_unique}[/]")
        else:
            try:
                parsed_entries, mtproto_hits, socks_hits, invalid_count, proxy_like_hits = mtproto_checker.fetch_mtproto_entries(
                    raw_url,
                    timeout=max(int(runtime_cfg.get("timeout", 5)), 5),
                    log_func=safe_print
                )
                added_unique = _merge_mtproto_entries(entries_map, parsed_entries)
                safe_print(
                    f"[dim]>> Из URL получено Telegram proxy-ссылок: {proxy_like_hits}, "
                    f"MTProto: {mtproto_hits}, SOCKS: {socks_hits}, "
                    f"invalid: {invalid_count}, добавлено уникальных: {added_unique}[/]"
                )
            except Exception as e:
                safe_print(f"[bold red]Ошибка загрузки Telegram proxy URL:[/] {e}")
                return

    if getattr(args, "reuse", False):
        reuse_path = runtime_cfg["output_file"]
        if os.path.exists(reuse_path):
            with open(reuse_path, 'r', encoding='utf-8', errors='ignore') as f:
                parsed_entries, mtproto_hits, socks_hits, invalid_count, proxy_like_hits = mtproto_checker.parse_mtproto_content(f.read())
            added_unique = _merge_mtproto_entries(entries_map, parsed_entries)
            safe_print(
                f"[dim]>> Reuse Telegram proxy: proxy-ссылок: {proxy_like_hits}, "
                f"MTProto: {mtproto_hits}, SOCKS: {socks_hits}, "
                f"invalid: {invalid_count}, добавлено уникальных: {added_unique}[/]"
            )
        else:
            safe_print(f"[yellow]Reuse-файл не найден: {reuse_path}[/]")

    full = list(entries_map.values())
    if getattr(args, "shuffle", False):
        random.shuffle(full)

    if getattr(args, "number", None):
        try:
            limit = int(args.number)
            if limit > 0:
                full = full[:limit]
        except Exception:
            pass

    safe_print(f"[dim]>> Уникальных Telegram proxy к проверке: {len(full)}[/]")
    if not full:
        safe_print("[bold red]Нет Telegram proxy для проверки.[/]")
        return

    safe_print(f"[dim]Telegram proxy crypto backend: {mtproto_checker.describe_crypto_backend(runtime_cfg, full)}[/]")

    all_dc_candidates = mtproto_checker.rank_telegram_dcs(limit=0)
    dc_limit = int(runtime_cfg.get("dc_probe_limit", 3) or 3)
    dc_candidates = all_dc_candidates[:dc_limit] if dc_limit > 0 else list(all_dc_candidates)
    runtime_cfg["dc_candidates"] = dc_candidates
    runtime_cfg["all_dc_candidates"] = all_dc_candidates

    runtime_cfg["threads"] = min(int(runtime_cfg.get("threads", 1) or 1), len(full))
    if runtime_cfg["threads"] < 1:
        runtime_cfg["threads"] = 1

    progress_columns = [
        SpinnerColumn(style="bold yellow"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="dim", complete_style="green", finished_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
    ]

    console.print(
        f"\n[magenta]Запуск {runtime_cfg['threads']} Telegram proxy воркеров "
        f"для {len(full)} прокси...[/]"
    )
    if dc_candidates:
        dc_desc = ", ".join(
            f"dc{item['dc_id']}"
            + (f"({item['probe_ms']}ms)" if item.get("probe_ms") is not None else "")
            for item in dc_candidates
        )
        console.print(f"[dim]Telegram DC order: {dc_desc}[/]")
    if runtime_cfg.get("max_ping_ms", 0) > 0:
        console.print(
            f"[dim]Фильтр ping Telegram proxy: TCP RTT <= {runtime_cfg['max_ping_ms']} ms "
            f"(время MTProto handshake не фильтруется)[/]"
        )

    mtproto_log_buffer = []
    with Progress(*progress_columns, console=console, transient=False) as progress:
        task_id = progress.add_task("[cyan]Checking Telegram proxies...", total=len(full))
        results, all_results = mtproto_checker.run_mtproto_check(
            full,
            runtime_cfg,
            log_func=mtproto_log_buffer.append,
            progress_callback=lambda: progress.advance(task_id, 1)
        )

    if runtime_cfg.get("fetch_promo_data", True):
        promo_limit = int(runtime_cfg.get("promo_probe_limit", 0) or 0)
        limit_suffix = f", limit={promo_limit}" if promo_limit > 0 else ""
        safe_print(
            f"[dim]MTProto promo enrichment: threads={runtime_cfg.get('promo_threads', 1)}, "
            f"timeout={runtime_cfg.get('promo_timeout', runtime_cfg.get('timeout'))}s{limit_suffix}...[/]"
        )
        mtproto_checker.enrich_promo_results(all_results, runtime_cfg)

    for log_line in _decorate_mtproto_promo_logs(mtproto_log_buffer, all_results):
        safe_print(log_line)

    results.sort(key=lambda x: x[1])

    connect_only_results = [
        item for item in all_results
        if item.get("status") == "connect_only" and item.get("entry")
    ]
    live_count = len([item for item in all_results if item.get("status") == "live"])
    connect_only_count = len(connect_only_results)
    drop_count = len([item for item in all_results if item.get("status") == "drop"])
    unreachable_count = len([item for item in all_results if item.get("status") == "proxy_unreachable"])
    soft_fail_count = len([item for item in all_results if item.get("status") == "soft_fail"])
    failed_count = len([item for item in all_results if item.get("status") == "fail"])

    preserve_empty_main = (
        not results
        and os.path.exists(runtime_cfg["output_file"])
        and (connect_only_count > 0 or soft_fail_count > 0)
    )
    if preserve_empty_main:
        safe_print(
            f"[yellow]MTProto: 0 LIVE, основной файл не обнулён: {runtime_cfg['output_file']}[/]"
        )
    else:
        with open(runtime_cfg["output_file"], 'w', encoding='utf-8') as f:
            for item in results:
                f.write(item[0] + '\n')

    if runtime_cfg.get("save_connect_only", True):
        preserve_empty_conn = (
            not connect_only_results
            and os.path.exists(runtime_cfg["connect_only_output_file"])
            and soft_fail_count > 0
        )
        if preserve_empty_conn:
            safe_print(
                f"[yellow]MTProto: 0 CONN, sidecar не обнулён: {runtime_cfg['connect_only_output_file']}[/]"
            )
        else:
            with open(runtime_cfg["connect_only_output_file"], 'w', encoding='utf-8') as f:
                for item in connect_only_results:
                    entry = item["entry"]
                    f.write((entry.get("canonical_url") or entry.get("original_url")) + '\n')

    auto_debug_attempts = live_count == 0 and (connect_only_count > 0 or soft_fail_count > 0)
    if runtime_cfg.get("debug_attempts", False) or auto_debug_attempts:
        mtproto_checker.write_attempt_diagnostics(runtime_cfg["attempts_output_file"], all_results)
        safe_print(f"[dim]MTProto attempt diagnostics: {runtime_cfg['attempts_output_file']}[/]")

    promo_summary_text = ""
    if runtime_cfg.get("fetch_promo_data", True):
        promo_summary = mtproto_checker.summarize_promo_results(all_results)
        mtproto_checker.write_promo_diagnostics(runtime_cfg["promo_output_file"], all_results)
        promo_summary_text = _format_mtproto_promo_summary(promo_summary)
        safe_print(f"[dim]MTProto promo data: {runtime_cfg['promo_output_file']}[/]")
        if int(promo_summary.get("auth_required") or 0) > 0:
            safe_print(
                "[yellow]MTProto promo требует авторизованную session: "
                "запусти `python v2rayChecker.py --mtproto-login` один раз.[/]"
            )

    if results:
        promo_by_proxy = _build_mtproto_promo_lookup(all_results)
        table = Table(title=f"Telegram proxy Results (Топ 15 из {len(results)})", box=box.ROUNDED)
        table.add_column("Ping", justify="right", style="green")
        table.add_column("Server", justify="left", overflow="fold")
        table.add_column("Promo", justify="left", overflow="fold")

        for item in results[:15]:
            parsed_entry, _ = mtproto_checker.parse_mtproto_url(item[0])
            if parsed_entry:
                proxy_kind = parsed_entry.get("proxy_kind", "mtproto")
                label = f"{parsed_entry['label']} [{proxy_kind}]"
            else:
                label = "telegram proxy"
            if len(label) > 50:
                label = label[:47] + "..."
            promo_label = (
                mtproto_checker.format_promo_display(promo_by_proxy.get(item[0]))
                if runtime_cfg.get("fetch_promo_data", True)
                else "off"
            )
            table.add_row(f"{item[1]} ms", label, promo_label or "unknown")
        console.print(table)

    conn_suffix = (
        f" CONN sidecar: {runtime_cfg['connect_only_output_file']}."
        if runtime_cfg.get("save_connect_only", True)
        else ""
    )
    safe_print(
        f"\n[bold green]Telegram proxy готово! LIVE: {live_count}. "
        f"CONN: {connect_only_count}. DROP: {drop_count}. UNREACH: {unreachable_count}. "
        f"SOFT: {soft_fail_count}. FAIL: {failed_count}. "
        f"{promo_summary_text + '. ' if promo_summary_text else ''}"
        f"Результат в: {runtime_cfg['output_file']}.{conn_suffix}[/]"
    )
    if runtime_cfg.get("max_ping_ms", 0) > 0 and drop_count > 0:
        safe_print(
            f"[yellow]Подсказка:[/] {drop_count} Telegram proxy живы, но отфильтрованы по TCP RTT > "
            f"{runtime_cfg['max_ping_ms']} ms. Для проверки именно живых прокси поставь `Telegram proxy ping = 0`."
        )


def run_mtproto_login_logic(args):
    if not MTPROTO_AVAILABLE or mtproto_checker is None:
        safe_print("[bold red]MTProto checker module не найден.[/]")
        return

    runtime_cfg = build_mtproto_runtime_cfg(args)
    ok, err = mtproto_checker.validate_runtime_config(runtime_cfg)
    if not ok:
        safe_print(f"[bold red]MTProto config error:[/] {err}")
        return

    proxy_entry = None
    if getattr(args, "url", None):
        raw_url = args.url.strip()
        if mtproto_checker.is_telegram_proxy_link(raw_url):
            proxy_entry, parse_error = mtproto_checker.parse_mtproto_url(raw_url)
            if not proxy_entry:
                safe_print(f"[bold red]Некорректная Telegram proxy ссылка для login:[/] {parse_error}")
                return
        else:
            safe_print("[yellow]--mtproto-login использует -u только если это tg://proxy или t.me/proxy ссылка; login будет напрямую[/]")

    session_file = runtime_cfg.get("promo_session_file", "mtproto_promo")
    safe_print(f"[cyan]MTProto promo login: session file = {session_file}.session[/]")
    if proxy_entry:
        safe_print(f"[cyan]MTProto promo login через proxy: {proxy_entry.get('label')}[/]")
    else:
        safe_print("[cyan]MTProto promo login напрямую к Telegram[/]")
    safe_print("[dim]Telegram active session будет отображаться как MK_XrayChecker[/]")

    if not Confirm.ask(
        "Подтверждаю: использую свой аккаунт, не для спама/скама, не для AI/data scraping, "
        "понимаю риск ограничений Telegram при нарушении ToS",
        default=False,
    ):
        safe_print("[yellow]MTProto promo login отменён.[/]")
        return

    phone, code_callback, password_callback = _build_mtproto_login_callbacks()

    try:
        result = mtproto_checker.login_promo_session(
            runtime_cfg,
            proxy_entry=proxy_entry,
            phone=phone,
            code_callback=code_callback,
            password=password_callback,
        )
    except Exception as exc:
        safe_print(f"[bold red]MTProto promo login failed:[/] {exc}")
        return

    username = result.get("username")
    name = result.get("name")
    user_label = f"@{username}" if username else (name or result.get("user_id") or "authorized user")
    safe_print(f"[green]✓ MTProto promo session authorized: {user_label}. Теперь можно запускать --mtproto.[/]")


def run_logic(args):
    global CORE_PATH, CORE_FLAVOR, CTRL_C

    if getattr(args, "mtproto_login", False):
        run_mtproto_login_logic(args)
        return

    if getattr(args, "mtproto", False):
        run_mtproto_logic(args)
        return
    
    def signal_handler(sig, frame):
        global CTRL_C
        CTRL_C = True
        safe_print("[bold red]CTRL+C - остановка...[/]")
        signal_router_mode = _bool_value(getattr(args, "router_mode", GLOBAL_CFG.get("router_mode", False)), False)
        signal_cleanup_mode = normalize_cleanup_mode(
            getattr(args, "cleanup_mode", GLOBAL_CFG.get("core_cleanup_mode", "owned")),
            default=normalize_cleanup_mode(GLOBAL_CFG.get("core_cleanup_mode", "owned"))
        )
        if signal_router_mode and signal_cleanup_mode == "all":
            signal_cleanup_mode = "owned"
        cleanup_stale_cores(CORE_PATH, signal_cleanup_mode)
        sys.exit(0)

    import signal
    signal.signal(signal.SIGINT, signal_handler)

    requested_engine = str(getattr(args, "engine", GLOBAL_CFG.get("preferred_core", "auto"))).strip().lower()
    if requested_engine not in ("auto", "xray", "mihomo"):
        requested_engine = "auto"
    router_mode = _bool_value(getattr(args, "router_mode", GLOBAL_CFG.get("router_mode", False)), False)
    cleanup_mode = normalize_cleanup_mode(
        getattr(args, "cleanup_mode", GLOBAL_CFG.get("core_cleanup_mode", "owned")),
        default=normalize_cleanup_mode(GLOBAL_CFG.get("core_cleanup_mode", "owned"))
    )
    if router_mode and cleanup_mode == "all":
        safe_print("[yellow]Router mode активен: cleanup mode 'all' переключен на 'owned'[/]")
        cleanup_mode = "owned"

    core_arg = (args.core or "").strip()
    CORE_PATH = ""

    # Если указан кастомный путь/имя ядра через -c, пробуем его первым
    if core_arg and core_arg.lower() not in ("auto", "xray", "v2ray", "mihomo", "clash-meta"):
        CORE_PATH = shutil.which(core_arg)
        if not CORE_PATH and os.path.exists(core_arg):
            CORE_PATH = os.path.abspath(core_arg)

    if not CORE_PATH:
        token = core_arg.lower()
        search_mode = requested_engine
        if token in ("xray", "v2ray"):
            search_mode = "xray"
        elif token in ("mihomo", "clash-meta"):
            search_mode = "mihomo"

        candidates = build_core_candidates(search_mode)
        for c in candidates:
            resolved = shutil.which(c)
            if resolved:
                CORE_PATH = resolved
                break
            if os.path.exists(c):
                CORE_PATH = os.path.abspath(c)
                break
    
    if not CORE_PATH and XRAY_INSTALLER_AVAILABLE:
        preferred_core = requested_engine
        if preferred_core not in ("xray", "mihomo"):
            preferred_core = str(GLOBAL_CFG.get("preferred_core", "xray")).strip().lower()
        if preferred_core not in ("xray", "mihomo"):
            preferred_core = "xray"
        safe_print(f"[yellow]>> Ядро не найдено, попытка автоустановки ({preferred_core})...[/]")
        try:
            if hasattr(xray_installer, "ensure_core_installed"):
                CORE_PATH = xray_installer.ensure_core_installed(GLOBAL_CFG, preferred_core=preferred_core)
            elif preferred_core == "mihomo":
                safe_print("[yellow]Текущая версия xray_installer.py не умеет ставить mihomo автоматически[/]")
            else:
                CORE_PATH = xray_installer.ensure_xray_installed(GLOBAL_CFG)
            
            if CORE_PATH:
                CORE_FLAVOR = detect_core_flavor(CORE_PATH)
                core_label = "Mihomo" if CORE_FLAVOR == "mihomo" else "Xray"
                safe_print(f"[green]✓ {core_label} установлен: {CORE_PATH}[/]")
                GLOBAL_CFG['core_path'] = CORE_PATH
                
                ok, err = save_main_config(GLOBAL_CFG)
                if ok:
                    safe_print(f"[dim]Путь к ядру сохранён в {CONFIG_FILE}[/]")
                else:
                    safe_print(f"[yellow]Не удалось сохранить конфиг: {err}[/]")
        except Exception as e:
            safe_print(f"[red]Ошибка автоустановки ядра: {e}[/]")
    
    if not CORE_PATH:
        safe_print(f"[bold red]\\n[ERROR] Ядро (xray/v2ray/mihomo) не найдено![/]")
        safe_print(f"[dim]Xray: https://github.com/XTLS/Xray-core/releases[/]")
        safe_print(f"[dim]Mihomo: https://github.com/MetaCubeX/mihomo/releases[/]")
        return

    CORE_FLAVOR = detect_core_flavor(CORE_PATH)
    if requested_engine != "auto" and CORE_FLAVOR != requested_engine:
        safe_print(
            f"[bold red][ERROR] Выбран режим ядра '{requested_engine}', "
            f"но найдено ядро '{CORE_FLAVOR}': {CORE_PATH}[/]"
        )
        if requested_engine == "xray":
            safe_print("[dim]Укажите путь к xray через --core или установите xray в bin/xray(.exe)[/]")
        else:
            safe_print("[dim]Укажите путь к mihomo через --core или установите mihomo в bin/mihomo(.exe)[/]")
        return

    safe_print(f"[dim]Core detected: {CORE_PATH} ({CORE_FLAVOR})[/]")
    safe_print(f"[dim]Engine mode: {requested_engine}[/]")
    if router_mode:
        safe_print(f"[bold cyan]Router mode: ВКЛ[/] [dim](safe cleanup: {cleanup_mode})[/]")
    if CORE_FLAVOR == "mihomo":
        safe_print("[yellow]Mihomo mode: проверка идёт по одному прокси на процесс ядра[/]")

    safe_print(f"[yellow]>> Очистка зависших процессов ядра (mode: {cleanup_mode})...[/]")
    killed_count, skipped_foreign, effective_mode = cleanup_stale_cores(CORE_PATH, cleanup_mode)
    if effective_mode == "none":
        safe_print("[dim]>> Очистка отключена (--cleanup-mode none)[/]")
    else:
        if killed_count > 0:
            safe_print(f"[green]>> Убито старых процессов: {killed_count}[/]")
        if effective_mode == "owned" and skipped_foreign > 0:
            safe_print(f"[dim]>> Пропущено чужих процессов: {skipped_foreign}[/]")
    time.sleep(0.5)
    
    lines = {}
    total_found_raw = 0
    
    if args.file:
        fpath = args.file.strip('"')
        if os.path.exists(fpath):
            safe_print(f"[cyan]>> Чтение файла: {fpath}[/]")
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                file_payload = f.read()
                parsed, count = parse_content(file_payload)
                total_found_raw += count
                _merge_proxy_entries(lines, parsed)
                safe_print(f"[dim]>> Прямых ссылок в файле: {len(parsed)}[/]")

                sub_urls = extract_subscription_urls(file_payload)
                if sub_urls:
                    safe_print(f"[cyan]>> Найдено URL-подписок в файле: {len(sub_urls)}[/]")
                    before_sub_merge = len(lines)
                    fetched_sub_total = 0
                    for sub_url in sub_urls:
                        links = fetch_url(sub_url)
                        fetched_sub_total += len(links)
                        _merge_proxy_entries(lines, links)
                    added_unique = len(lines) - before_sub_merge
                    safe_print(
                        f"[dim]>> Из подписок получено: {fetched_sub_total}, "
                        f"добавлено уникальных: {added_unique}[/]"
                    )

    if args.url:
        links = fetch_url(args.url)
        _merge_proxy_entries(lines, links)

    if AGGREGATOR_AVAILABLE and getattr(args, 'agg', False):
        sources_map = GLOBAL_CFG.get("sources", {})
        cats = args.agg_cats if args.agg_cats else list(sources_map.keys())
        kws = args.agg_filter if args.agg_filter else []
        country_filters = args.agg_country if getattr(args, "agg_country", None) else GLOBAL_CFG.get("agg_countries", [])
        if isinstance(country_filters, str):
            country_filters = country_filters.split()
        country_filters = [str(item).strip() for item in (country_filters or []) if str(item).strip()]
        if country_filters:
            safe_print(f"[dim]>> Agg country filter: {' '.join(country_filters)}[/]")
        try:
            agg_links = aggregator.get_aggregated_links(
                sources_map,
                cats,
                kws,
                country_filters=country_filters,
                log_func=safe_print,
                console=console
            )
            _merge_proxy_entries(lines, agg_links)
        except: pass

    if hasattr(args, 'direct_list') and args.direct_list:
        parsed_agg, _ = parse_content("\n".join(args.direct_list))
        _merge_proxy_entries(lines, parsed_agg)

    if args.reuse and os.path.exists(args.output):
        with open(args.output, 'r', encoding='utf-8') as f:
            parsed, count = parse_content(f.read())
            _merge_proxy_entries(lines, parsed)

    full = list(lines.values())
    if args.shuffle:
        random.shuffle(full)
    safe_print(f"[dim]>> Уникальных прокси к проверке: {len(full)}[/]")
    if not full:
        safe_print(f"[bold red]Нет прокси для проверки.[/]")
        return

    xray_list = []
    mihomo_list = []
    mihomo_path = CORE_PATH if CORE_FLAVOR == "mihomo" else ""
    needs_mihomo = [p for p in full if protocol_capability(p) == "mihomo"]
    unsupported = [p for p in full if protocol_capability(p) == "unsupported"]
    for p in full:
        parsed = parse_proxy_url(p) or {}
        for diagnostic in parsed.get("diagnostics", []):
            safe_print(f"[yellow]{get_proxy_tag(p)}: {diagnostic}[/]")
    for p in unsupported:
        safe_print(f"[yellow]Unsupported proxy skipped: {get_proxy_tag(p)}[/]")
    if CORE_FLAVOR == "mihomo":
        mihomo_list = [p for p in full if p not in unsupported]
    elif needs_mihomo:
        candidates = build_core_candidates("mihomo")
        for c in candidates:
            resolved = shutil.which(c)
            if resolved:
                mihomo_path = resolved
                break
            if os.path.exists(c):
                mihomo_path = os.path.abspath(c)
                break
        
        if mihomo_path:
            for p in full:
                if protocol_capability(p) == "mihomo":
                    mihomo_list.append(p)
                elif protocol_capability(p) == "xray":
                    xray_list.append(p)
        else:
            safe_print("[yellow]Mihomo-required proxies skipped: core not found.[/]")
            xray_list = [p for p in full if protocol_capability(p) == "xray"]
    else:
        xray_list = [p for p in full if protocol_capability(p) == "xray"]

    results = []
    
    try:
        max_ping_ms = int(getattr(args, "max_ping", GLOBAL_CFG.get("max_ping_ms", 0)) or 0)
    except Exception:
        max_ping_ms = 0
    if max_ping_ms < 0:
        max_ping_ms = 0
    
    speed_config_map = {
        "timeout": GLOBAL_CFG.get("speed_download_timeout", 10),
        "conn_timeout": GLOBAL_CFG.get("speed_connect_timeout", 5),
        "max_mb": GLOBAL_CFG.get("speed_max_mb", 5),
        "min_kb": GLOBAL_CFG.get("speed_min_kb", 1)
    }
    speed_semaphore = Semaphore(GLOBAL_CFG.get("speed_check_threads", 3))

    progress_columns = [
        SpinnerColumn(style="bold yellow"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="dim", complete_style="green", finished_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
    ]

    def _process_batch(batch_full, override_flavor, override_core_path, base_threads, task_desc):
        global CORE_FLAVOR, CORE_PATH, CTRL_C
        if not batch_full:
            return []
            
        old_flavor = CORE_FLAVOR
        old_path = CORE_PATH
        
        CORE_FLAVOR = override_flavor
        CORE_PATH = override_core_path

        if CORE_FLAVOR == "mihomo":
            threads = min(base_threads, len(batch_full))
            if threads < 1: threads = 1
            console.print(f"\n[magenta]Запуск {threads} параллельных воркеров (mihomo) для {len(batch_full)} прокси...[/]")
            console.print("[dim]Mihomo: 1 процесс = 1 прокси одновременно[/]")
        else:
            p_per_batch = GLOBAL_CFG.get("proxies_per_batch", 50)
            needed_cores = (len(batch_full) + p_per_batch - 1) // p_per_batch
            threads = min(base_threads, needed_cores)
            if threads < 1: threads = 1
            console.print(f"\n[magenta]Запуск {threads} ядер (пачек) для {len(batch_full)} прокси...[/]")

        if max_ping_ms > 0:
            console.print(f"[dim]Фильтр ping: <= {max_ping_ms} ms[/]")

        chunks = list(split_list(batch_full, threads))
        ports = []
        curr_p = args.lport
        for chunk in chunks:
            ports.append(curr_p)
            curr_p += len(chunk) + 10 
            
        batch_results = []
        with Progress(*progress_columns, console=console, transient=False) as progress:
            task_id = progress.add_task(f"[cyan]{task_desc}", total=len(batch_full))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for i in range(len(chunks)):
                    ft = executor.submit(
                        Checker, chunks[i], ports[i], args.domain, args.timeout, 
                        args.t2exec, args.t2kill, args.speed_check, args.speed_test_url, args.sort_by,
                        speed_config_map, speed_semaphore,
                        GLOBAL_CFG.get("max_internal_threads", 50), max_ping_ms,
                        progress, task_id
                    )
                    futures.append(ft)
                
                try:
                    for f in as_completed(futures):
                        chunk_result = f.result()
                        if chunk_result:
                            batch_results.extend(chunk_result)
                except KeyboardInterrupt:
                    CTRL_C = True
                    executor.shutdown(wait=False)

        CORE_FLAVOR = old_flavor
        CORE_PATH = old_path
        return batch_results

    if xray_list:
        results.extend(_process_batch(xray_list, CORE_FLAVOR, CORE_PATH, args.threads, "Checking proxies..."))
    
    if mihomo_list:
        results.extend(_process_batch(mihomo_list, "mihomo", mihomo_path, args.threads, "Checking hy2 proxies (Mihomo)..."))

    if args.sort_by == "speed":
        results.sort(key=lambda x: x[2], reverse=True)
    else:
        results.sort(key=lambda x: x[1])
    
    with open(args.output, 'w', encoding='utf-8') as f:
        for r in results:
            value = ({k: v for k, v in r[0].items() if k != "_native_mihomo"}
                     if isinstance(r[0], dict) else r[0])
            f.write((json.dumps(value, ensure_ascii=False) if isinstance(value, dict) else value) + '\n')

    if results:
        table = Table(title=f"Результаты (Топ 15 из {len(results)})", box=box.ROUNDED)
        table.add_column("Ping", justify="right", style="green")
        if args.speed_check:
            table.add_column("Speed (Mbps)", justify="right", style="bold cyan")
        table.add_column("Tag / Protocol", justify="left", overflow="fold")

        for r in results[:15]:
            tag_display = get_proxy_tag(r[0])
            if len(tag_display) > 50: tag_display = tag_display[:47] + "..."
            if args.speed_check:
                table.add_row(f"{r[1]} ms", f"{r[2]}", tag_display)
            else:
                table.add_row(f"{r[1]} ms", tag_display)
        console.print(table)
            
    safe_print(f"\n[bold green]Готово! Рабочих: {len(results)}. Результат в: {args.output}[/]")

def print_banner():
    console.clear()
    
    logo_str = BACKUP_LOGO
    font_name = "default"

    if text2art:
        try:
            font_name = random.choice(LOGO_FONTS)
            logo_str = text2art("Xchecker", font=font_name, chr_ignore=True)
        except Exception:
            logo_str = BACKUP_LOGO

    if not logo_str or not logo_str.strip():
        logo_str = BACKUP_LOGO

    logo_text = Text(logo_str, style="cyan bold", no_wrap=True, overflow="crop")
    
    panel = Panel(
        logo_text,
        title=f"[bold magenta]MK_XRAYchecker v{__version__}[/] [dim](font: {font_name})[/]",
        subtitle="[bold red]by mkultra69 with HATE[/]",
        border_style="cyan",
        box=box.DOUBLE,
        expand=False, 
        padding=(1, 2)
    )
    
    console.print(panel, justify="center")
    console.print("[dim]GitHub: https://github.com/MKultra6969 | Telegram: https://t.me/MKplusULTRA[/]", justify="center")
    console.print("─"*75, style="dim", justify="center")
    
    try:
        MAIN_LOGGER.log("MK_XRAYchecker by mkultra69 with HATE")
        MAIN_LOGGER.log("https://t.me/MKplusULTRA")
    except: pass

def kill_all_cores_manual():
    killed_count = 0
    target_names = list(ALL_CORE_PROCESS_NAMES)
    
    safe_print("[yellow]>> Принудительный сброс ВСЕХ ядер...[/]")
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and any(name in proc.info['name'].lower() for name in target_names):
                proc.kill()
                killed_count += 1
                safe_print(f"[green]✓ Убит PID {proc.info['pid']}[/]")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    if OS_SYSTEM == "windows":
        try:
            for image_name in ("xray.exe", "mihomo.exe"):
                result = subprocess.run(
                    ["taskkill", "/F", "/IM", image_name, "/T"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    killed_count += result.stdout.count("SUCCESS")
        except:
            pass
    
    for port in range(10000, 11000):
        if is_port_in_use(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)
                    s.connect(('127.0.0.1', port))
            except:
                pass
    
    time.sleep(1.0)
    remaining = 0
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and any(name in proc.info['name'].lower() for name in target_names):
                remaining += 1
        except:
            pass
    
    safe_print(f"[bold green]✓ СБРОС ЗАВЕРШЕН: убито {killed_count} ядер[/]")
    if remaining > 0:
        safe_print(f"[yellow]⚠ Осталось {remaining} процессов (перезапуск через 3с)[/]")
        time.sleep(3)
        kill_all_cores_manual()
    else:
        safe_print("[bold green]✅ Все чисто![/]")

def _render_interactive_status(mt_cfg):
    router_state = "ON" if _bool_value(GLOBAL_CFG.get("router_mode", False), False) else "OFF"
    cleanup_state = normalize_cleanup_mode(GLOBAL_CFG.get("core_cleanup_mode", "owned"))

    status_grid = Table.grid(expand=True, padding=(0, 1))
    status_grid.add_column(style="cyan", justify="right", width=18)
    status_grid.add_column(style="white")
    status_grid.add_row("Version", f"v{__version__}")
    status_grid.add_row("Ядро", str(GLOBAL_CFG.get("preferred_core", "auto")))
    status_grid.add_row(
        "Ping",
        f"Xray/Mihomo: {GLOBAL_CFG.get('max_ping_ms', 500)} ms | "
        f"MTProto: {mt_cfg.get('max_ping_ms', 0)} ms"
    )
    status_grid.add_row("Router/Cleanup", f"{router_state} / {cleanup_state}")
    status_grid.add_row(
        "Output",
        f"{GLOBAL_CFG.get('output_file', 'sortedProxy.txt')} | "
        f"{mt_cfg.get('output_file', 'sortedMtproto.txt')}"
    )
    status_grid.add_row(
        "MTProto Probe",
        f"{mt_cfg.get('probe_policy', 'balanced')} "
        f"(connect/rpc retries {mt_cfg.get('connect_retries', 1)}/{mt_cfg.get('rpc_retries', 1)})"
    )
    console.print(Panel(status_grid, title="Текущее состояние", border_style="dim"))


def _render_interactive_menu(title, rows, subtitle=None):
    try:
        console.clear()
    except Exception:
        pass

    print_banner()
    mt_cfg = get_mtproto_config(GLOBAL_CFG)
    _render_interactive_status(mt_cfg)

    table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED, expand=True, title=title)
    table.add_column("№", style="cyan", width=4, justify="center")
    table.add_column("Действие", style="white", ratio=2, no_wrap=True)
    table.add_column("Описание", style="dim", ratio=5)

    for key, action, description in rows:
        table.add_row(str(key), action, description)

    console.print(table)
    if subtitle:
        console.print(f"[dim]{subtitle}[/]")

    return Prompt.ask("[bold yellow]>[/] Выберите действие", choices=[str(row[0]) for row in rows])


def _build_interactive_defaults():
    cfg_agg_countries = GLOBAL_CFG.get("agg_countries", [])
    if isinstance(cfg_agg_countries, str):
        cfg_agg_countries = cfg_agg_countries.split()

    return {
        "file": None, "url": None, "reuse": False,
        "domain": GLOBAL_CFG['test_domain'],
        "timeout": GLOBAL_CFG['timeout'],
        "lport": GLOBAL_CFG['local_port_start'],
        "threads": GLOBAL_CFG['threads'],
        "core": GLOBAL_CFG['core_path'],
        "engine": GLOBAL_CFG.get("preferred_core", "auto"),
        "router_mode": _bool_value(GLOBAL_CFG.get("router_mode", False), False),
        "cleanup_mode": normalize_cleanup_mode(GLOBAL_CFG.get("core_cleanup_mode", "owned")),
        "t2exec": GLOBAL_CFG['core_startup_timeout'],
        "t2kill": GLOBAL_CFG['core_kill_delay'],
        "output": GLOBAL_CFG['output_file'],
        "max_ping": GLOBAL_CFG.get("max_ping_ms", 500),
        "shuffle": GLOBAL_CFG['shuffle'],
        "number": None,
        "direct_list": None,
        "agg_country": list(cfg_agg_countries),
        "speed_check": GLOBAL_CFG['check_speed'],
        "speed_test_url": GLOBAL_CFG['speed_test_url'],
        "sort_by": GLOBAL_CFG['sort_by'],
        "menu": True,
        "mtproto": False,
        "mtproto_login": False,
    }


def _run_interactive_args(defaults):
    if not defaults.get("mtproto") and Confirm.ask("Включить тест скорости?", default=False):
        defaults["speed_check"] = True
        defaults["sort_by"] = "speed"
    else:
        defaults["speed_check"] = False
        defaults["sort_by"] = "ping"

    args = SimpleNamespace(**defaults)

    safe_print("\n[yellow]>>> Инициализация проверки...[/]")
    time.sleep(0.5)

    try:
        run_logic(args)
    except Exception as e:
        safe_print(f"[bold red]CRITICAL ERROR: {e}[/]")
        import traceback
        error_data = traceback.format_exc()
        MAIN_LOGGER.log(f"CRASH REPORT:\n{error_data}")

        if Confirm.ask("[bold magenta]Произошла ошибка. Загрузить лог на paste.rs для отладки?[/]", default=True):
            upload_log_to_service(is_crash=True)

        traceback.print_exc()

    Prompt.ask("\n[bold]Нажмите Enter чтобы вернуться в меню...[/]", password=False)


def interactive_menu():
    while True:
        mt_cfg = get_mtproto_config(GLOBAL_CFG)
        main_rows = [
            ("1", "Проверка", "Xray/Mihomo, MTProto и агрегатор"),
            ("2", "Настройки", "Ядро и ping-пороги"),
            ("3", "Сервис", "Сброс ядер и загрузка логов"),
            ("0", "Выход", "Закрыть программу"),
        ]
        main_choice = _render_interactive_menu("Главное меню", main_rows)

        if main_choice == "0":
            sys.exit()

        if main_choice == "1":
            check_rows = [
                ("1", "Xray: Файл", "Загрузить прокси из .txt файла"),
                ("2", "Xray: Ссылка", "Загрузить прокси по URL"),
                ("3", "Xray: Перепроверка", f"Проверить заново {GLOBAL_CFG['output_file']}"),
                ("4", "MTProto: Файл", "Telegram proxy checker из файла"),
                ("5", "MTProto: Ссылка", "Telegram proxy checker по ссылке или URL списка"),
                ("6", "MTProto: Reuse", f"Проверить заново {mt_cfg.get('output_file', 'sortedMtproto.txt')}"),
                ("0", "Назад", "Вернуться в главное меню"),
            ]
            if AGGREGATOR_AVAILABLE:
                check_rows.insert(6, ("7", "Агрегатор", "Скачать базы, объединить и проверить"))

            action = _render_interactive_menu("Проверка", check_rows)
            if action == "0":
                continue

            defaults = _build_interactive_defaults()
            cfg_agg_countries = defaults["agg_country"]

            if action == "1":
                defaults["file"] = Prompt.ask("[cyan][?][/] Путь к файлу").strip('"')
                if not defaults["file"]:
                    continue
            elif action == "2":
                defaults["url"] = Prompt.ask("[cyan][?][/] URL ссылки").strip()
                if not defaults["url"]:
                    continue
            elif action == "3":
                defaults["reuse"] = True
            elif action in ("4", "5", "6"):
                defaults["mtproto"] = True
                defaults["output"] = mt_cfg.get("output_file", "sortedMtproto.txt")
                defaults["threads"] = int(mt_cfg.get("threads", 20) or 20)
                defaults["timeout"] = int(mt_cfg.get("timeout", 5) or 5)
                defaults["max_ping"] = int(mt_cfg.get("max_ping_ms", 0) or 0)
                defaults["speed_check"] = False
                defaults["sort_by"] = "ping"

                if action == "4":
                    defaults["file"] = Prompt.ask("[cyan][?][/] Путь к MTProto файлу").strip('"')
                    if not defaults["file"]:
                        continue
                elif action == "5":
                    defaults["url"] = Prompt.ask("[cyan][?][/] MTProto ссылка или URL списка").strip()
                    if not defaults["url"]:
                        continue
                else:
                    defaults["reuse"] = True
            elif action == "7" and AGGREGATOR_AVAILABLE:
                console.print(Panel(
                    f"Доступные категории: [green]{', '.join(GLOBAL_CFG.get('sources', {}).keys())}[/]",
                    title="Агрегатор"
                ))
                cats = Prompt.ask("Введите категории (через пробел)", default="1 2").split()
                kws = Prompt.ask("Фильтр (ключевые слова через пробел)", default="").split()
                country_default = " ".join(cfg_agg_countries)
                country_filters = Prompt.ask(
                    "Фильтр стран ISO2 (через пробел, опционально)",
                    default=country_default
                ).split()
                defaults["agg_country"] = country_filters

                sources_map = GLOBAL_CFG.get("sources", {})
                try:
                    raw_links = aggregator.get_aggregated_links(
                        sources_map,
                        cats,
                        kws,
                        country_filters=country_filters,
                        console=console
                    )
                    if not raw_links:
                        safe_print("[bold red]Ничего не найдено агрегатором.[/]")
                        time.sleep(2)
                        continue
                    defaults["direct_list"] = raw_links
                except Exception as e:
                    safe_print(f"[bold red]Ошибка агрегатора: {e}[/]")
                    continue

            _run_interactive_args(defaults)
            continue

        if main_choice == "2":
            settings_rows = [
                ("1", "Свитч ядра", f"Режим: {GLOBAL_CFG.get('preferred_core', 'auto')}"),
                ("2", "Ping Xray/Mihomo", f"{GLOBAL_CFG.get('max_ping_ms', 500)} ms (0 = off)"),
                ("3", "Ping MTProto", f"{mt_cfg.get('max_ping_ms', 0)} ms (0 = off)"),
                ("4", "Crypto MTProto", str(mt_cfg.get("crypto_backend", "auto"))),
                ("5", "Probe MTProto", f"{mt_cfg.get('probe_policy', 'balanced')} ({mt_cfg.get('connect_retries', 1)}/{mt_cfg.get('rpc_retries', 1)})"),
                ("6", "CONN MTProto", "save" if _bool_value(mt_cfg.get("save_connect_only", True), True) else "off"),
                ("7", "Login MTProto", "Авторизовать session для Promo"),
                ("0", "Назад", "Вернуться в главное меню"),
            ]
            action = _render_interactive_menu("Настройки", settings_rows)
            if action == "0":
                continue

            if action == "1":
                new_engine = Prompt.ask(
                    "Режим ядра",
                    choices=["auto", "xray", "mihomo"],
                    default=str(GLOBAL_CFG.get("preferred_core", "auto"))
                )
                GLOBAL_CFG["preferred_core"] = new_engine
                if new_engine == "xray":
                    GLOBAL_CFG["core_path"] = "xray"
                elif new_engine == "mihomo":
                    GLOBAL_CFG["core_path"] = "mihomo"
                else:
                    GLOBAL_CFG["core_path"] = "auto"

                ok, err = save_main_config(GLOBAL_CFG)
                if ok:
                    safe_print(f"[green]✓ Ядро переключено: mode={new_engine}, core_path={GLOBAL_CFG['core_path']}[/]")
                else:
                    safe_print(f"[yellow]Не удалось сохранить конфиг: {err}[/]")
                time.sleep(1.0)
                continue

            if action == "2":
                raw_ping = Prompt.ask(
                    "Максимальный ping (мс), 0 = выключить фильтр",
                    default=str(GLOBAL_CFG.get("max_ping_ms", 500))
                )
                try:
                    max_ping = int(raw_ping)
                    if max_ping < 0:
                        max_ping = 0
                    GLOBAL_CFG["max_ping_ms"] = max_ping
                    ok, err = save_main_config(GLOBAL_CFG)
                    if ok:
                        safe_print(f"[green]✓ Порог ping сохранён: {max_ping} ms[/]")
                    else:
                        safe_print(f"[yellow]Не удалось сохранить конфиг: {err}[/]")
                except Exception:
                    safe_print("[yellow]Некорректное значение ping[/]")
                time.sleep(1.0)
                continue

            if action == "3":
                raw_ping = Prompt.ask(
                    "Максимальный ping для MTProto (мс), 0 = выключить фильтр",
                    default=str(mt_cfg.get("max_ping_ms", 0))
                )
                try:
                    max_ping = int(raw_ping)
                    if max_ping < 0:
                        max_ping = 0
                    GLOBAL_CFG.setdefault("mtproto", {})
                    GLOBAL_CFG["mtproto"]["max_ping_ms"] = max_ping
                    ok, err = save_main_config(GLOBAL_CFG)
                    if ok:
                        safe_print(f"[green]✓ MTProto ping порог сохранён: {max_ping} ms[/]")
                    else:
                        safe_print(f"[yellow]Не удалось сохранить конфиг: {err}[/]")
                except Exception:
                    safe_print("[yellow]Некорректное значение ping[/]")
                time.sleep(1.0)
                continue

            if action == "4":
                crypto_backend = Prompt.ask(
                    "Режим crypto backend для MTProto",
                    choices=["auto", "safe", "unsafe"],
                    default=str(mt_cfg.get("crypto_backend", "auto"))
                )
                GLOBAL_CFG.setdefault("mtproto", {})
                GLOBAL_CFG["mtproto"]["crypto_backend"] = crypto_backend
                ok, err = save_main_config(GLOBAL_CFG)
                if ok:
                    safe_print(f"[green]✓ MTProto crypto backend сохранён: {crypto_backend}[/]")
                else:
                    safe_print(f"[yellow]Не удалось сохранить конфиг: {err}[/]")
                time.sleep(1.0)
                continue

            if action == "5":
                probe_policy = Prompt.ask(
                    "MTProto probe policy",
                    choices=["strict", "balanced", "telegram_like"],
                    default=str(mt_cfg.get("probe_policy", "balanced"))
                )
                try:
                    connect_retries = int(Prompt.ask(
                        "MTProto connect retries (0-3)",
                        default=str(mt_cfg.get("connect_retries", 1))
                    ))
                    rpc_retries = int(Prompt.ask(
                        "MTProto RPC retries (0-3)",
                        default=str(mt_cfg.get("rpc_retries", 1))
                    ))
                    connect_retries = max(0, min(3, connect_retries))
                    rpc_retries = max(0, min(3, rpc_retries))
                except Exception:
                    safe_print("[yellow]Некорректное значение retry[/]")
                    time.sleep(1.0)
                    continue

                GLOBAL_CFG.setdefault("mtproto", {})
                GLOBAL_CFG["mtproto"]["probe_policy"] = probe_policy
                GLOBAL_CFG["mtproto"]["connect_retries"] = connect_retries
                GLOBAL_CFG["mtproto"]["rpc_retries"] = rpc_retries
                ok, err = save_main_config(GLOBAL_CFG)
                if ok:
                    safe_print(
                        f"[green]✓ MTProto probe сохранён: {probe_policy}, "
                        f"connect/rpc retries={connect_retries}/{rpc_retries}[/]"
                    )
                else:
                    safe_print(f"[yellow]Не удалось сохранить конфиг: {err}[/]")
                time.sleep(1.0)
                continue

            if action == "6":
                save_conn = Confirm.ask(
                    "Сохранять CONN в отдельный sidecar-файл?",
                    default=_bool_value(mt_cfg.get("save_connect_only", True), True)
                )
                GLOBAL_CFG.setdefault("mtproto", {})
                GLOBAL_CFG["mtproto"]["save_connect_only"] = save_conn
                if save_conn and not GLOBAL_CFG["mtproto"].get("connect_only_output_file"):
                    GLOBAL_CFG["mtproto"]["connect_only_output_file"] = "sortedMtproto.conn.txt"
                ok, err = save_main_config(GLOBAL_CFG)
                if ok:
                    safe_print(f"[green]✓ MTProto CONN sidecar: {'on' if save_conn else 'off'}[/]")
                else:
                    safe_print(f"[yellow]Не удалось сохранить конфиг: {err}[/]")
                time.sleep(1.0)
                continue

            if action == "7":
                args = SimpleNamespace(**_build_interactive_defaults())
                args.mtproto_login = True
                args.mtproto = False
                if Confirm.ask("Логиниться через конкретный MTProto proxy?", default=False):
                    args.url = Prompt.ask("[cyan][?][/] MTProto proxy ссылка").strip()
                    if not args.url:
                        continue
                run_mtproto_login_logic(args)
                Prompt.ask("\n[bold]Нажмите Enter чтобы вернуться в меню...[/]", password=False)
                continue

        if main_choice == "3":
            service_rows = [
                ("1", "Сброс ядер", "Убить все процессы xray/mihomo"),
                ("2", "Загрузить лог", "Отправить последние события на paste.rs"),
                ("0", "Назад", "Вернуться в главное меню"),
            ]
            action = _render_interactive_menu("Сервис", service_rows)
            if action == "0":
                continue

            if action == "1":
                kill_all_cores_manual()
                Prompt.ask("\nНажмите Enter...", password=False)
                continue

            if action == "2":
                upload_log_to_service()
                Prompt.ask("\nНажмите Enter...", password=False)
                continue

def main():
    skip_self_update = ("--no-update" in sys.argv) or (os.environ.get("MKXRAY_SKIP_SELF_UPDATE") == "1")
    if UPDATER_AVAILABLE and not skip_self_update:
        try:
            updater.maybe_self_update(GLOBAL_CFG)
        except Exception as e:
            safe_print(f"[yellow]Предупреждение: Ошибка проверки обновлений: {e}[/]")

    agg_country_default = GLOBAL_CFG.get("agg_countries", [])
    if isinstance(agg_country_default, str):
        agg_country_default = agg_country_default.split()
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--menu", action="store_true")
    parser.add_argument("-f", "--file")
    parser.add_argument("-u", "--url")
    parser.add_argument("--reuse", action="store_true")
    parser.add_argument("--mtproto", action="store_true", help="Запустить отдельный checker MTProto proxy (tg://proxy / t.me/proxy)")
    parser.add_argument("--mtproto-login", action="store_true", help="Один раз авторизовать Telethon session для MTProto promo data")
    parser.add_argument("--mtproto-crypto", choices=["auto", "safe", "unsafe"], default=None, help="Crypto backend для MTProto: auto/safe/unsafe")
    
    parser.add_argument("-t", "--timeout", type=int, default=GLOBAL_CFG['timeout'])
    parser.add_argument("-l", "--lport", type=int, default=GLOBAL_CFG['local_port_start'])
    parser.add_argument("-T", "--threads", type=int, default=GLOBAL_CFG['threads'])
    parser.add_argument("-c", "--core", default=GLOBAL_CFG['core_path'])
    parser.add_argument("--engine", choices=["auto", "xray", "mihomo"], default=GLOBAL_CFG.get("preferred_core", "auto"), help="Режим выбора ядра: auto/xray/mihomo")
    parser.add_argument("--router-mode", action="store_true", default=_bool_value(GLOBAL_CFG.get("router_mode", False), False), help="Безопасный режим для роутеров/OpenWRT (не убивать чужие ядра)")
    parser.add_argument("--cleanup-mode", choices=["owned", "all", "none"], default=normalize_cleanup_mode(GLOBAL_CFG.get("core_cleanup_mode", "owned")), help="Очистка старых процессов ядра: owned/all/none")
    parser.add_argument("--t2exec", type=float, default=GLOBAL_CFG['core_startup_timeout'])
    parser.add_argument("--t2kill", type=float, default=GLOBAL_CFG['core_kill_delay'])
    parser.add_argument("-o", "--output", default=GLOBAL_CFG['output_file'])
    parser.add_argument("-d", "--domain", default=GLOBAL_CFG['test_domain'])
    parser.add_argument("--max-ping", type=int, default=GLOBAL_CFG.get("max_ping_ms", 500), dest="max_ping", help="Отсев по ping (мс). 0 = отключить")
    parser.add_argument("-s", "--shuffle", action='store_true', default=GLOBAL_CFG['shuffle'])
    parser.add_argument("-n", "--number", type=int)
    parser.add_argument("--agg", action="store_true", help="Запустить агрегатор")
    parser.add_argument("--agg-cats", nargs='+', help="Категории для агрегатора (например: 1 2)")
    parser.add_argument("--agg-filter", nargs='+', help="Ключевые слова для фильтра (например: vless reality)")
    parser.add_argument("--agg-country", nargs='+', default=agg_country_default, help="Фильтр агрегатора по странам ISO2 (например: RU DE GB)")
    parser.add_argument("--speed", action="store_true", dest="speed_check", help="Включить тест скорости")
    parser.add_argument("--sort", choices=["ping", "speed"], default=GLOBAL_CFG['sort_by'], dest="sort_by", help="Метод сортировки")
    parser.add_argument("--speed-url", default=GLOBAL_CFG['speed_test_url'], dest="speed_test_url")
    parser.add_argument("--self-test", action="store_true", help="Запустить самопроверку URL парсинга")
    parser.add_argument("--debug", action="store_true", help="Debug режим (proxies_per_batch=1, threads=1)")
    parser.add_argument("--no-update", action="store_true", help="Пропустить проверку обновлений")

    if len(sys.argv) == 1:
        interactive_menu()
    else:
        args = parser.parse_args()
        
        if getattr(args, 'self_test', False):
            print("Running URL parsing self-test...")
            success = _self_test_clean_url()
            success = _self_test_subscription_url_parsing() and success
            if MTPROTO_AVAILABLE and mtproto_checker is not None:
                print("Running Telegram proxy parsing self-test...")
                success = mtproto_checker.run_parser_self_test(log_func=safe_print) and success
            sys.exit(0 if success else 1)
        
        if getattr(args, 'debug', False):
            GLOBAL_CFG['debug_mode'] = True
            GLOBAL_CFG['proxies_per_batch'] = 1
            GLOBAL_CFG['threads'] = 1
            safe_print("[yellow][DEBUG MODE] proxies_per_batch=1, threads=1[/]")

        args = apply_mtproto_arg_defaults(args)
        
        if args.menu: interactive_menu()
        else:
            print(Fore.CYAN + "MK_XRAYchecker by mkultra69 with HATE" + Style.RESET_ALL)
            run_logic(args)

if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Exit.{Style.RESET_ALL}")
    finally:
        try: shutil.rmtree(TEMP_DIR)
        except: pass


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

# мяу мяу мяу мяу мяу мяу мяу
