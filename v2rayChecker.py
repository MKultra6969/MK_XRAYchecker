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
# ║                           VERSION 1.0.4                                 ║
# ║             В случае багов/недочётов создайте issue на github           ║
# ║                                                                         ║
# +═════════════════════════════════════════════════════════════════════════+


import argparse
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

# ВЕРСИЯ СКРИПТА
# Формат: MAJOR.MINOR.PATCH (SemVer)
__version__ = "1.1.0"

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
# Xray Shadowsocks: официально перечисленные поддерживаемые методы (актуально на 2026-01-05)
SS_ALLOWED_METHODS = {
    # Shadowsocks 2022
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",

    # AEAD (legacy)
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

# Устаревшие методы, которые НЕ поддерживаются (для справки):
# aes-128-cfb, aes-192-cfb, aes-256-cfb, aes-128-ctr, aes-256-ctr,
# camellia-128-cfb, camellia-256-cfb, rc4-md5, bf-cfb, и т.д.
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

# --- Self-Update Module ---
try:
    import updater
    UPDATER_AVAILABLE = True
    try:
        if updater.apply_pending_update_if_any():
            print("[UPDATER] Обновления применены. Перезапустите скрипт для корректной работы.")
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
    "proxies_per_batch": 50, # Сколько проксей обрабатывает ОДНО ядро xray
    "max_internal_threads": 50, # Сколько ПАРАЛЛЕЛЬНЫХ проверок идет внутри одного ядра
    "timeout": 3,         # Таймаут (повышать в случае огромного пинга)
    "local_port_start": 10000, # Отвечает за то, с какого конкретно порта будут запускаться ядра, 1080 > 1081 > 1082 = три потока(три ядра)
    "test_domain": "https://www.google.com/generate_204", # Ссылка по которой будут чекаться прокси, можно использовать другие в случае блокировок в разных странах.(http://cp.cloudflare.com/generate_204)
    "output_file": "sortedProxy.txt", # имя файла с отфильтрованными проксями
    "core_startup_timeout": 2.5, # Максимальное время ожидания старта ядра(ну если тупит)
    "core_kill_delay": 0.05,     # Задержка после УБИЙСТВА
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

    # АВТОУСТАНОВКА XRAY CORE
    # autoinstall_xray: True = автоматически скачать и установить Xray если не найден
    #                   False = спрашивать пользователя
    "autoinstall_xray": True,
    
    # xray_version: "latest" или конкретная версия типа "v1.8.10"
    "xray_version": "latest",
}

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
            config_to_write = DEFAULT_CONFIG.copy()
            del config_to_write["sources"] 
            
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config_to_write, f, indent=4)
            print(f"Created default {CONFIG_FILE}")
        except: pass
        cfg = DEFAULT_CONFIG.copy()
        cfg["sources"] = loaded_sources
        return cfg
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
        
        config = DEFAULT_CONFIG.copy()
        config.update(user_config)
        
        config["sources"] = loaded_sources
        
        has_new_keys = False
        keys_to_check = [k for k in DEFAULT_CONFIG.keys() if k != "sources"]
        
        for key in keys_to_check:
            if key not in user_config:
                has_new_keys = True
                break
        
        if has_new_keys:
            try:
                print(f">> Обновление {CONFIG_FILE}: добавлены новые параметры...")
                save_cfg = config.copy()
                if "sources" in save_cfg: del save_cfg["sources"]
                
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(save_cfg, f, indent=4)
            except Exception as e:
                print(f"Warning: Не удалось обновить конфиг файл: {e}")

        return config
    except Exception as e:
        print(f"Error loading config: {e}")
        cfg = DEFAULT_CONFIG.copy()
        cfg["sources"] = loaded_sources
        return cfg

GLOBAL_CFG = load_config()

PROTO_HINTS = ("vless://", "vmess://", "trojan://", "hysteria2://", "hy2://", "ss://")

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

URL_FINDER = re.compile(
    r'(?:vless|vmess|trojan|hysteria2|hy2)://[^\s"\'<>]+|(?<![A-Za-z0-9+])ss://[^\s"\'<>]+',
    re.IGNORECASE
)

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

def _self_test_clean_url():
    """
    Юнит-тест для clean_url(): проверяет корректность декодирования
    HTML entities и URL encoding для параметров VLESS/REALITY.
    Запускать: python v2rayChecker.py --self-test
    
    Returns:
        bool: True если все тесты прошли
    """
    test_cases = [
        # (входная строка, ожидаемая подстрока после очистки)
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
                safe_print(f"[green]✓ PASS[/]: {raw[:60]}...")
            else:
                safe_print(f"[red]✗ FAIL[/]: {raw[:60]}...")
                safe_print(f"[dim]  Got: {cleaned[:100]}[/]")
        else:
            passed += 1
    
    safe_print(f"\n[bold]Self-test: {passed}/{len(test_cases)} passed[/]")
    return passed == len(test_cases)

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
    
    console.print("[yellow]📤 Загрузка логов на MK_Paste...[/]")
    
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            content = "".join(lines[-1000:])
        
        payload = {
            "content": content,
            "language": "text",
            "ttl_minutes": 1440,
            "burn_after_read": False,
            "visibility": "unlisted",
            "tags": "v2rayChecker,crash" if is_crash else "v2rayChecker"
        }
        
        resp = requests.post(
            "https://paste.mk69.su/api/paste",
            json=payload,
            headers={"User-Agent": "v2rayChecker/1.0"},
            timeout=20
        )
        
        if resp.status_code in (200, 201):
            data = resp.json()
            url = f"https://paste.mk69.su{data['url']}"
            
            console.print(Panel(
                f"[bold cyan]{url}[/]\n[dim]Expires in 24h[/]",
                title="✅ Upload Success",
                border_style="green"
            ))
            return url
        else:
            console.print(f"[red]❌ HTTP {resp.status_code}[/]")
            console.print(f"[dim]{resp.text[:200]}[/]")
            
            console.print("[yellow]↻ Trying fallback (paste.rs)...[/]")
            resp_fallback = requests.post(
                "https://paste.rs",
                data=content.encode('utf-8'),
                headers={"Content-Type": "text/plain"},
                timeout=15
            )
            
            if resp_fallback.status_code in (200, 201):
                fallback_url = resp_fallback.text.strip()
                console.print(Panel(
                    f"[bold green]{fallback_url}[/]",
                    title="✅ Fallback Success"
                ))
                return fallback_url
                
    except Exception as e:
        console.print(f"[red]❌ Upload failed: {e}[/]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()[:500]}[/]")
    
    return None

TEMP_DIR = tempfile.mkdtemp()
OS_SYSTEM = platform.system().lower()
CORE_PATH = ""
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


def split_list(lst, n):
    if n <= 0: return []
    k, m = divmod(len(lst), n)
    return (lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

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
        if any(marker in decoded for marker in PROTO_HINTS):
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

def parse_content(text):
    unique_links = set()
    raw_hits = 0

    for payload in _payload_variants(text):
        matches = URL_FINDER.findall(payload)
        raw_hits += len(matches)
        for item in matches:
            cleaned = clean_url(item.rstrip(';,)]}'))
            if cleaned and len(cleaned) > 15:
                unique_links.add(cleaned)

    return list(unique_links), raw_hits or len(unique_links)

def fetch_url(url):
    try:
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
    
def parse_vless(url):
    try:
        url = clean_url(url)
        if not url.startswith("vless://"): return None

        main_part = url
        tag = "vless"
        if '#' in url:
            parts = url.split('#', 1)
            main_part = parts[0]
            tag = urllib.parse.unquote(parts[1]).strip()

        if '¬' in main_part: main_part = main_part.split('¬')[0]

        match = re.search(r'vless://([^@]+)@([^:]+):(\d+)', main_part)
        if not match: return None

        uuid = match.group(1).strip()
        address = match.group(2).strip()
        port = int(match.group(3))

        params = {}
        if '?' in main_part:
            query = main_part.split('?', 1)[1]
            query = re.split(r'[^\w\-\=\&\%(\.)]', query)[0]
            params = urllib.parse.parse_qs(query)

        def get_p(key, default=""):
            val = params.get(key, [default])
            v = val[0].strip()
            return re.sub(r'[^\x20-\x7E]', '', v) if v else default
        
        net_type = get_p("type", "tcp").lower()
        net_type = re.sub(r"[^a-z0-9]", "", net_type)
        if net_type in ["http", "h2"]:
            net_type = "xhttp"
        elif net_type == "httpupgrade":
            net_type = "xhttp"

        flow = get_p("flow", "").lower().strip()
        flow = FLOW_ALIASES.get(flow, flow)
        
        if flow in ["none", "xtls-rprx-direct", "xtls-rprx-origin", 
                    "xtls-rprx-splice", "xtls-rprx-direct-udp443"]:
            flow = ""
        
        if flow not in FLOW_ALLOWED:
            flow = ""
        
        security = get_p("security", "none").lower()
        if security not in ["tls", "reality", "none", "auto"]:
            security = "none"
        
        if flow and security not in ["tls", "reality"]:
            if GLOBAL_CFG.get("debug_mode"):
                safe_print(f"[yellow][DEBUG] Dropping flow={flow} for security={security} (flow requires tls/reality)[/]")
            flow = ""

        pbk = get_p("pbk", "")
        # ВАЛИДАЦИЯ: Строгая проверка X25519 ключа (base64url -> 32 байта)
        if pbk:
            try:
                missing_padding = len(pbk) % 4
                pbk_padded = pbk + '=' * (4 - missing_padding) if missing_padding else pbk
                
                decoded = base64.urlsafe_b64decode(pbk_padded)
                
                if len(decoded) != 32:
                    if GLOBAL_CFG.get("debug_mode"):
                        safe_print(f"[yellow][DEBUG] Dropping invalid PBK (len{len(decoded)}!=32): {pbk}[/]")
                    pbk = ""
            except Exception as e:
                if GLOBAL_CFG.get("debug_mode"):
                    safe_print(f"[yellow][DEBUG] Dropping invalid PBK (decode error): {pbk} ({e})[/]")
                pbk = ""

        if pbk and security == "tls":
            security = "reality"

        sid = get_p("sid", "")
        # Валидация ShortId: должен быть hex и чётной длины
        if sid:
            sid = re.sub(r"[^0-9a-fA-F]", "", sid)
            if len(sid) % 2 != 0:
                if GLOBAL_CFG.get("debug_mode"):
                    safe_print(f"[yellow][DEBUG] Fixing odd SID length {len(sid)}: {sid} -> 0{sid}[/]")
                sid = "0" + sid
            
            if not REALITY_SID_RE.match(sid):
                sid = ""

        return {
            "protocol": "vless",
            "uuid": uuid,
            "address": address,
            "port": port,
            "encryption": get_p("encryption", "none"),
            "type": net_type,
            "security": security,
            "path": urllib.parse.unquote(get_p("path", "")),
            "host": get_p("host", ""),
            "sni": get_p("sni", ""),
            "fp": get_p("fp", ""),
            "alpn": get_p("alpn", ""),
            "serviceName": get_p("serviceName", ""),
            "mode": get_p("mode", ""),
            "pbk": pbk,
            "sid": sid,
            "flow": flow,
            "headerType": get_p("headerType", ""),
            "tag": tag
        }
    except Exception as e:
        return None

def parse_vmess(url):
    try:
        url = clean_url(url)
        if not url.startswith("vmess://"): return None

        if '@' in url:
            if '#' in url:
                main_part, tag = url.split('#', 1)
                tag = urllib.parse.unquote(tag).strip()
            else:
                main_part = url
                tag = "vmess"

            match = re.search(r'vmess://([^@]+)@([^:]+):(\d+)', main_part)
            if match:
                uuid = match.group(1).strip()
                address = match.group(2).strip()
                port = int(match.group(3))

                params = {}
                if '?' in main_part:
                    query = main_part.split('?', 1)[1]
                    params = urllib.parse.parse_qs(query)

                def get_p(key, default=""):
                    val = params.get(key, [default])
                    return val[0] if val else default
                
                try: aid = int(get_p("aid", "0"))
                except: aid = 0
                
                raw_path = get_p("path", "")
                final_path = urllib.parse.unquote(raw_path)

                net_type = get_p("type", "tcp").lower()
                if net_type in ["http", "h2", "httpupgrade"]:
                    net_type = "xhttp"
            
                return {
                    "protocol": "vmess",
                    "uuid": uuid,
                    "address": address,
                    "port": int(port),
                    "type": net_type,
                    "security": get_p("security", "none"),
                    "path": final_path,
                    "host": get_p("host", ""),
                    "sni": get_p("sni", ""),
                    "fp": get_p("fp", ""),
                    "alpn": get_p("alpn", ""),
                    "serviceName": get_p("serviceName", ""),
                    "aid": aid,
                    "scy": get_p("encryption", "auto"),
                    "tag": tag
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
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            data = json.loads(decoded)
            
            net_type = data.get("net", "tcp")
            if net_type in ["http", "h2", "httpupgrade"]:
                net_type = "xhttp"
            
            return {
                "protocol": "vmess",
                "uuid": data.get("id"),
                "address": data.get("add"),
                "port": int(data.get("port", 0)),
                "aid": int(data.get("aid", 0)),
                "type": net_type,
                "security": data.get("tls", "") if data.get("tls") else "none",
                "path": data.get("path", ""),
                "host": data.get("host", ""),
                "sni": data.get("sni", ""),
                "fp": data.get("fp", ""),
                "alpn": data.get("alpn", ""),
                "scy": data.get("scy", "auto"),
                "tag": data.get("ps", tag)
            }
        except:
            pass

        return None
    except Exception as e:
        safe_print(f"{Fore.RED}[VMESS ERROR] {e}{Style.RESET_ALL}")
        return None
    
def parse_trojan(url):
    try:
        if '#' in url:
            url_clean, tag = url.split('#', 1)
        else:
            url_clean = url
            tag = "trojan"
        
        parsed = urllib.parse.urlparse(url_clean)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not parsed.hostname or not parsed.port:
            return None

        return {
            "protocol": "trojan",
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": int(parsed.port),
            "security": params.get("security", ["tls"])[0],
            "sni": params.get("sni", [""])[0] or params.get("peer", [""])[0],
            "type": params.get("type", ["tcp"])[0],
            "path": params.get("path", [""])[0],
            "host": params.get("host", [""])[0],
            "tag": urllib.parse.unquote(tag).strip()
        }
    except: return None

def parse_ss(url):
    try:
        if '#' in url:
            url_clean, tag = url.split('#', 1)
        else:
            url_clean = url
            tag = "ss"
        
        parsed = urllib.parse.urlparse(url_clean)
        
        if '@' in url_clean:
            userinfo = parsed.username
            try:
                if userinfo and ':' not in userinfo:
                    missing_padding = len(userinfo) % 4
                    if missing_padding: userinfo += '=' * (4 - missing_padding)
                    decoded_info = base64.b64decode(userinfo).decode('utf-8')
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
            decoded = base64.b64decode(b64).decode('utf-8')
            if '@' not in decoded: return None
            method_pass, addr_port = decoded.rsplit('@', 1)
            method, password = method_pass.split(':', 1)
            address, port = addr_port.rsplit(':', 1)

        if not address or not port: return None
        
        method_lower = method.lower().strip()
        
        # Алиасы для chacha20
        if method_lower == "chacha20-poly1305":
            method_lower = "chacha20-ietf-poly1305"
        elif method_lower == "xchacha20-poly1305":
            method_lower = "xchacha20-ietf-poly1305"
        
        # Валидация: проверяем что cipher поддерживается Xray
        # CFB/CTR/OFB stream ciphers вызывают Exit 23!
        if method_lower not in SS_ALLOWED_METHODS:
            if GLOBAL_CFG.get("debug_mode"):
                safe_print(f"[yellow][DEBUG] Dropping SS link: unsupported cipher '{method}' (only AEAD allowed)[/]")
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
    try:
        url = url.replace("hy2://", "hysteria2://")
        if '#' in url:
            url_clean, tag = url.split('#', 1)
        else:
            url_clean = url
            tag = "hy2"
            
        parsed = urllib.parse.urlparse(url_clean)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not parsed.hostname or not parsed.port:
            return None

        return {
            "protocol": "hysteria2",
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": int(parsed.port),
            "sni": params.get("sni", [""])[0],
            "insecure": params.get("insecure", ["0"])[0] == "1",
            "obfs": params.get("obfs", ["none"])[0],
            "obfs_password": params.get("obfs-password", [""])[0],
            "tag": urllib.parse.unquote(tag).strip()
        }
    except: return None

def get_proxy_tag(url):
    tag = "proxy"
    try:
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
        proxy_url = clean_url(proxy_url)
        proxy_conf = None
        
        if proxy_url.startswith("vless://"): proxy_conf = parse_vless(proxy_url)
        elif proxy_url.startswith("vmess://"): proxy_conf = parse_vmess(proxy_url)
        elif proxy_url.startswith("trojan://"): proxy_conf = parse_trojan(proxy_url)
        elif proxy_url.startswith("ss://"): proxy_conf = parse_ss(proxy_url)
        elif proxy_url.startswith("hy"): proxy_conf = parse_hysteria2(proxy_url)
        
        if not proxy_conf or not proxy_conf.get("address"): return None
        if not is_valid_port(proxy_conf.get("port")): return None
        
        if proxy_conf["protocol"] in ["vless", "vmess"]:
            if not is_valid_uuid(proxy_conf.get("uuid")): return None
        
        net_type = proxy_conf.get("type", "tcp").lower()
        header_type = proxy_conf.get("headerType", "").lower()
        
        if net_type == "http" or header_type == "http":
            return None
        
        streamSettings = {}
        security = proxy_conf.get("security", "none").lower()
        
        original_net_type = net_type
        if net_type in ["ws", "websocket"]:
            net_type = "xhttp"
        elif net_type in ["grpc", "gun"]:
            net_type = "xhttp"  
        elif net_type in ["http", "h2"]:
            net_type = "xhttp"
        elif net_type == "httpupgrade":
            net_type = "xhttp"
        elif net_type not in ["tcp", "kcp", "quic", "xhttp"]:
            net_type = "tcp"
        
        if proxy_conf["protocol"] in ["vless", "vmess", "trojan"]:
            if security == "auto":
                security = "none"
            
            streamSettings = {
                "network": net_type,
                "security": security
            }
            
            alpn_val = None
            raw_alpn = proxy_conf.get("alpn")
            if raw_alpn:
                if isinstance(raw_alpn, list): 
                    alpn_val = raw_alpn
                elif isinstance(raw_alpn, str): 
                    alpn_val = raw_alpn.split(",")
            
            tls_settings = {
                "serverName": proxy_conf.get("sni") or proxy_conf.get("host") or "",
                "allowInsecure": True,
                "fingerprint": proxy_conf.get("fp", "chrome")
            }
            
            if alpn_val: 
                tls_settings["alpn"] = alpn_val
            
            if security == "tls":
                streamSettings["tlsSettings"] = tls_settings
            elif security == "reality":
                if not proxy_conf.get("pbk"): 
                    return None
                s_id = proxy_conf.get("sid", "")
                if len(s_id) % 2 != 0: 
                    s_id = ""
                streamSettings["realitySettings"] = {
                    "publicKey": proxy_conf.get("pbk"),
                    "shortId": s_id,
                    "serverName": tls_settings["serverName"],
                    "fingerprint": tls_settings["fingerprint"],
                    "spiderX": "/"
                }
            
            path = proxy_conf.get("path") or "/"
            host = proxy_conf.get("host") or ""
            
            if net_type == "xhttp":
                mode = "auto"
                if original_net_type in ["grpc", "gun"]:
                    mode = "stream-up"
                    if not path or path == "/":
                        path = proxy_conf.get("serviceName") or "/"
                
                streamSettings["xhttpSettings"] = {
                    "path": path,
                    "host": host,
                    "mode": mode
                }
            elif net_type == "tcp":
                if proxy_conf.get("headerType") and proxy_conf.get("headerType").lower() != "none":
                    return None
            elif net_type == "kcp":
                streamSettings["kcpSettings"] = {
                    "header": {"type": proxy_conf.get("headerType") or "none"}
                }
            elif net_type == "quic":
                streamSettings["quicSettings"] = {
                    "security": proxy_conf.get("quicSecurity") or "none",
                    "key": proxy_conf.get("key") or "",
                    "header": {"type": proxy_conf.get("headerType") or "none"}
                }
        
        outbound = {
            "protocol": proxy_conf["protocol"],
            "tag": tag,
            "streamSettings": streamSettings
        }
        
        if proxy_conf["protocol"] == "shadowsocks":
            method = proxy_conf["method"].lower()
            if "chacha20-ietf" in method and "poly1305" not in method:
                method = "chacha20-ietf-poly1305"
            outbound["settings"] = {
                "servers": [{
                    "address": proxy_conf["address"],
                    "port": int(proxy_conf["port"]),
                    "method": method,
                    "password": proxy_conf["password"]
                }]
            }
            outbound.pop("streamSettings", None)
            
        elif proxy_conf["protocol"] == "trojan":
            outbound["settings"] = {
                "servers": [{
                    "address": proxy_conf["address"],
                    "port": int(proxy_conf["port"]),
                    "password": proxy_conf["uuid"]
                }]
            }
            
        elif proxy_conf["protocol"] == "hysteria2":
            hy2_settings = {
                "address": proxy_conf["address"],
                "port": int(proxy_conf["port"]),
                "users": [{"password": proxy_conf["uuid"]}]
            }
            if proxy_conf.get("obfs") and proxy_conf.get("obfs") != "none":
                hy2_settings["obfs"] = {
                    "type": proxy_conf["obfs"],
                    "password": proxy_conf.get("obfs_password", "")
                }
            outbound["settings"] = {"vnext": [hy2_settings]}
            outbound["streamSettings"] = {
                "security": "tls",
                "tlsSettings": {
                    "serverName": proxy_conf.get("sni", ""),
                    "allowInsecure": True,
                    "fingerprint": "chrome"
                }
            }
            if alpn_val: 
                outbound["streamSettings"]["tlsSettings"]["alpn"] = alpn_val
        else:
            vnext_user = {
                "id": proxy_conf["uuid"],
                "alterId": proxy_conf.get("aid", 0),
                "encryption": "none"
            }
            if proxy_conf["protocol"] == "vless" and proxy_conf.get("flow"):
                vnext_user["flow"] = proxy_conf.get("flow")
            
            outbound["settings"] = {
                "vnext": [{
                    "address": proxy_conf["address"],
                    "port": int(proxy_conf["port"]),
                    "users": [vnext_user]
                }]
            }
        
        return outbound
        
    except Exception as e:
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
        "log": {"loglevel": "warning"},  # warning для диагностики (none скрывает ошибки)
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
        safe_print(f"[dim]   Reproduce: xray run -test -c \"{dest_json}\"[/]")
        
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
    cmd = [core_path, "run", "-c", config_path] if "xray" in core_path.lower() else [core_path, "-c", config_path]
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

def Checker(proxyList, localPortStart, testDomain, timeOut, t2exec, t2kill, 
            checkSpeed=False, speedUrl="", sortBy="ping", speedCfg=None, 
            speedSemaphore=None, maxInternalThreads=50, 
            progress=None, task_id=None):
    
    current_live_results = []
    if speedCfg is None: speedCfg = {}

    configPath, valid_mapping, err = create_batch_config_file(proxyList, localPortStart, TEMP_DIR)
    if err or not valid_mapping:
        return current_live_results

    proc = run_core(CORE_PATH, configPath)
    if not proc:
        safe_print(f"[bold red][BATCH ERROR] Не удалось создать процесс ядра![/]")
        return current_live_results

    core_started = False
    start_time = time.time()
    max_wait = max(t2exec, 5.0)
    while (time.time() - start_time) < max_wait:
        poll_result = proc.poll()
        if poll_result is not None:
            exitcode = proc.returncode
            if exitcode == 0: break
            
            try:
                out_data, _ = proc.communicate(timeout=1)
                if out_data:
                     error_msg = out_data.strip()[-2000:] 
            except Exception as e:
                error_msg = f"Failed to read error output: {e}"
            
            safe_print(f"[bold red]BATCH FAILED[/] [yellow]Ядро не запустилось (Exit: {exitcode})[/]")
            safe_print(f"[dim]Error: {error_msg[:300]}[/]")
            
            save_failed_batch(configPath, error_msg, exitcode)
            
            kill_core(proc)
            return current_live_results
        if is_port_in_use(valid_mapping[0][1]):
            core_started = True
            break
        time.sleep(0.1)

    if core_started:
        time.sleep(0.3)

    if not core_started:
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
        except:
            try:
                proc.wait(timeout=0.5)
                error_msg = "Core failed silently"
            except:
                error_msg = "Core timeout"
        
        safe_print(f"[bold red]BATCH FAILED[/] [yellow]Ядро не запустилось (Exit: {exitcode})[/]")
        safe_print(f"[dim]Error: {error_msg[:300]}[/]")
        
        save_failed_batch(configPath, error_msg, exitcode)
            
        exit_code = proc.poll()
        
        kill_core(proc)
        return current_live_results
    
    def check_single_port(item):
        if CTRL_C: return None
        target_url, target_port = item
        
        proxy_speed = 0.0
        
        conf = None
        try:
            if target_url.startswith("vless://"): conf = parse_vless(target_url)
            elif target_url.startswith("vmess://"): conf = parse_vmess(target_url)
            elif target_url.startswith("ss://"): conf = parse_ss(target_url)
            elif target_url.startswith("trojan://"): conf = parse_trojan(target_url)
        except: pass
        
        addr_info = f"{conf['address']}:{conf['port']}" if conf else "unknown"
        proxy_tag = get_proxy_tag(target_url)
        
        ping_res, error_reason = check_connection(target_port, testDomain, timeOut)
        
        if ping_res:
            if checkSpeed:
                with (speedSemaphore if speedSemaphore else Lock()):
                    proxy_speed = check_speed_download(target_port, speedUrl, **speedCfg)
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

def run_logic(args):
    global CORE_PATH, CTRL_C
    
    def signal_handler(sig, frame):
        global CTRL_C
        CTRL_C = True
        safe_print("[bold red]CTRL+C - остановка...[/]")
        kill_all_cores_manual()
        sys.exit(0)

    import signal
    signal.signal(signal.SIGINT, signal_handler)

    CORE_PATH = shutil.which(args.core)
    if not CORE_PATH:
        # Стандартные места где может лежать ядро
        candidates = ["xray.exe", "xray", "v2ray.exe", "v2ray", "bin/xray.exe", "bin/xray"]
        for c in candidates:
             if os.path.exists(c):
                 CORE_PATH = os.path.abspath(c)
                 break
    
    if not CORE_PATH and XRAY_INSTALLER_AVAILABLE:
        safe_print("[yellow]>> Ядро (xray/v2ray) не найдено, попытка автоустановки...[/]")
        try:
            CORE_PATH = xray_installer.ensure_xray_installed(GLOBAL_CFG)
            
            if CORE_PATH:
                safe_print(f"[green]✓ Xray установлен: {CORE_PATH}[/]")
                GLOBAL_CFG['core_path'] = CORE_PATH
                
                try:
                    save_cfg = GLOBAL_CFG.copy()
                    if "sources" in save_cfg: del save_cfg["sources"]
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(save_cfg, f, indent=4)
                    safe_print(f"[dim]Путь к ядру сохранён в {CONFIG_FILE}[/]")
                except Exception as e:
                    safe_print(f"[yellow]Не удалось сохранить конфиг: {e}[/]")
        except Exception as e:
            safe_print(f"[red]Ошибка автоустановки Xray: {e}[/]")
    
    if not CORE_PATH:
        safe_print(f"[bold red]\\n[ERROR] Ядро (xray/v2ray) не найдено![/]")
        safe_print(f"[dim]Скачайте вручную: https://github.com/XTLS/Xray-core/releases[/]")
        return
        
    safe_print(f"[dim]Core detected: {CORE_PATH}[/]")

    safe_print(f"[yellow]>> Очистка зависших процессов ядра...[/]")
    killed_count = 0
    target_names = [os.path.basename(CORE_PATH).lower(), "xray.exe", "v2ray.exe", "xray", "v2ray"]
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in target_names:
                proc.kill()
                killed_count += 1
        except: pass
    
    if killed_count > 0: safe_print(f"[green]>> Убито старых процессов: {killed_count}[/]")
    time.sleep(0.5)
    
    lines = set()
    total_found_raw = 0
    
    if args.file:
        fpath = args.file.strip('"')
        if os.path.exists(fpath):
            safe_print(f"[cyan]>> Чтение файла: {fpath}[/]")
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                parsed, count = parse_content(f.read())
                total_found_raw += count
                lines.update(parsed)

    if args.url:
        links = fetch_url(args.url)
        lines.update(links)

    if AGGREGATOR_AVAILABLE and getattr(args, 'agg', False):
        sources_map = GLOBAL_CFG.get("sources", {})
        cats = args.agg_cats if args.agg_cats else list(sources_map.keys())
        kws = args.agg_filter if args.agg_filter else []
        try:
            agg_links = aggregator.get_aggregated_links(sources_map, cats, kws, log_func=safe_print, console=console)
            lines.update(agg_links)
        except: pass

    if hasattr(args, 'direct_list') and args.direct_list:
        parsed_agg, _ = parse_content("\n".join(args.direct_list))
        lines.update(parsed_agg)

    if args.reuse and os.path.exists(args.output):
        with open(args.output, 'r', encoding='utf-8') as f:
            parsed, count = parse_content(f.read())
            lines.update(parsed)

    full = list(lines)
    if not full:
        safe_print(f"[bold red]Нет прокси для проверки.[/]")
        return

    p_per_batch = GLOBAL_CFG.get("proxies_per_batch", 50)
    needed_cores = (len(full) + p_per_batch - 1) // p_per_batch
    threads = min(args.threads, needed_cores)
    if threads < 1: threads = 1

    chunks = list(split_list(full, threads))
    ports = []
    curr_p = args.lport
    for chunk in chunks:
        ports.append(curr_p)
        curr_p += len(chunk) + 10 
    
    results = []
    
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

    console.print(f"\n[magenta]Запуск {threads} ядер (пачек) для {len(full)} прокси...[/]")

    with Progress(*progress_columns, console=console, transient=False) as progress:
        task_id = progress.add_task("[cyan]Checking proxies...", total=len(full))
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for i in range(len(chunks)):
                ft = executor.submit(
                    Checker, chunks[i], ports[i], args.domain, args.timeout, 
                    args.t2exec, args.t2kill, args.speed_check, args.speed_test_url, args.sort_by,
                    speed_config_map, speed_semaphore,
                    GLOBAL_CFG.get("max_internal_threads", 50),
                    progress, task_id
                )
                futures.append(ft)
            
            try:
                for f in as_completed(futures):
                    chunk_result = f.result()
                    if chunk_result:
                        results.extend(chunk_result)
            except KeyboardInterrupt:
                CTRL_C = True
                executor.shutdown(wait=False)

    if args.sort_by == "speed":
        results.sort(key=lambda x: x[2], reverse=True)
    else:
        results.sort(key=lambda x: x[1])
    
    with open(args.output, 'w', encoding='utf-8') as f:
        for r in results:
            f.write(r[0] + '\n')

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
    console.print("[dim]GitHub: https://github.com/MKultra6969 | Telegram: https://t.me/MKextera[/]", justify="center")
    console.print("─"*75, style="dim", justify="center")
    
    try:
        MAIN_LOGGER.log("MK_XRAYchecker by mkultra69 with HATE")
        MAIN_LOGGER.log("https://t.me/MKextera")
    except: pass

def kill_all_cores_manual():
    killed_count = 0
    target_names = ["xray.exe", "v2ray.exe", "xray", "v2ray"]
    
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
            result = subprocess.run(
                ["taskkill", "/F", "/IM", "xray.exe", "/T"], 
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

def interactive_menu():
    while True:
        print_banner()
        
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED, expand=True)
        table.add_column("№", style="cyan", width=4, justify="center")
        table.add_column("Действие", style="white")
        table.add_column("Описание", style="dim")

        table.add_row("1", "Файл", "Загрузить прокси из .txt файла")
        table.add_row("2", "Ссылка", "Загрузить прокси по URL")
        table.add_row("3", "Перепроверка", f"Проверить заново {GLOBAL_CFG['output_file']}")
        
        if AGGREGATOR_AVAILABLE:
            table.add_row("4", "Агрегатор", "Скачать базы, объединить и проверить")
        
        table.add_row("5", "Сброс ядер", "Убить все процессы xray")
        table.add_row("6", "Загрузить лог", "Отправить последние события на paste.rs")
        table.add_row("0", "Выход", "Закрыть программу")
        
        console.print(f"[dim]Version: v{__version__}[/]")
        console.print(table)
        
        valid_choices = ["0", "1", "2", "3", "4", "5", "6"] if AGGREGATOR_AVAILABLE else ["0", "1", "2", "3", "5", "6"]
        ch = Prompt.ask("[bold yellow]>[/] Выберите действие", choices=valid_choices)
        
        if ch == '0':
            sys.exit()

        defaults = {
            "file": None, "url": None, "reuse": False,
            "domain": GLOBAL_CFG['test_domain'],
            "timeout": GLOBAL_CFG['timeout'], 
            "lport": GLOBAL_CFG['local_port_start'], 
            "threads": GLOBAL_CFG['threads'], 
            "core": GLOBAL_CFG['core_path'], 
            "t2exec": GLOBAL_CFG['core_startup_timeout'], 
            "t2kill": GLOBAL_CFG['core_kill_delay'], 
            "output": GLOBAL_CFG['output_file'], 
            "shuffle": GLOBAL_CFG['shuffle'], 
            "number": None,
            "direct_list": None,
            "speed_check": GLOBAL_CFG['check_speed'],
            "speed_test_url": GLOBAL_CFG['speed_test_url'],
            "sort_by": GLOBAL_CFG['sort_by'],
            "menu": True
        }
        
        if ch == '1':
            defaults["file"] = Prompt.ask("[cyan][?][/] Путь к файлу").strip('"')
            if not defaults["file"]: continue
            
        elif ch == '2':
            defaults["url"] = Prompt.ask("[cyan][?][/] URL ссылки").strip()
            if not defaults["url"]: continue
            
        elif ch == '3':
            defaults["reuse"] = True
            
        elif ch == '4' and AGGREGATOR_AVAILABLE:
            console.print(Panel(f"Доступные категории: [green]{', '.join(GLOBAL_CFG.get('sources', {}).keys())}[/]", title="Агрегатор"))
            cats = Prompt.ask("Введите категории (через пробел)", default="1 2").split()
            kws = Prompt.ask("Фильтр (ключевые слова через пробел)", default="").split()
            
            sources_map = GLOBAL_CFG.get("sources", {})
            try:
                raw_links = aggregator.get_aggregated_links(sources_map, cats, kws, console=console)
                if not raw_links:
                    safe_print("[bold red]Ничего не найдено агрегатором.[/]")
                    time.sleep(2)
                    continue
                defaults["direct_list"] = raw_links
            except Exception as e:
                safe_print(f"[bold red]Ошибка агрегатора: {e}[/]")
                continue
            
        elif ch == '5':
            kill_all_cores_manual()
            continue
        elif ch == '6':
            upload_log_to_service()
            Prompt.ask("\nНажмите Enter...", password=False)
            continue
        if Confirm.ask("Включить тест скорости?", default=False):
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

def main():
    if UPDATER_AVAILABLE:
        try:
            updater.maybe_self_update(GLOBAL_CFG)
        except Exception as e:
            safe_print(f"[yellow]Предупреждение: Ошибка проверки обновлений: {e}[/]")
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--menu", action="store_true")
    parser.add_argument("-f", "--file")
    parser.add_argument("-u", "--url")
    parser.add_argument("--reuse", action="store_true")
    
    parser.add_argument("-t", "--timeout", type=int, default=GLOBAL_CFG['timeout'])
    parser.add_argument("-l", "--lport", type=int, default=GLOBAL_CFG['local_port_start'])
    parser.add_argument("-T", "--threads", type=int, default=GLOBAL_CFG['threads'])
    parser.add_argument("-c", "--core", default=GLOBAL_CFG['core_path'])
    parser.add_argument("--t2exec", type=float, default=GLOBAL_CFG['core_startup_timeout'])
    parser.add_argument("--t2kill", type=float, default=GLOBAL_CFG['core_kill_delay'])
    parser.add_argument("-o", "--output", default=GLOBAL_CFG['output_file'])
    parser.add_argument("-d", "--domain", default=GLOBAL_CFG['test_domain'])
    parser.add_argument("-s", "--shuffle", action='store_true', default=GLOBAL_CFG['shuffle'])
    parser.add_argument("-n", "--number", type=int)
    parser.add_argument("--agg", action="store_true", help="Запустить агрегатор")
    parser.add_argument("--agg-cats", nargs='+', help="Категории для агрегатора (например: 1 2)")
    parser.add_argument("--agg-filter", nargs='+', help="Ключевые слова для фильтра (например: vless reality)")
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
            sys.exit(0 if success else 1)
        
        if getattr(args, 'debug', False):
            GLOBAL_CFG['debug_mode'] = True
            GLOBAL_CFG['proxies_per_batch'] = 1
            GLOBAL_CFG['threads'] = 1
            safe_print("[yellow][DEBUG MODE] proxies_per_batch=1, threads=1[/]")
        
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