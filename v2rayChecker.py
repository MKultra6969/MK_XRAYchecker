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
# ║                           VERSION 1.0.0 batch check                     ║
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
from datetime import datetime
from http.client import BadStatusLine, RemoteDisconnected
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import SimpleNamespace
from threading import Lock, Semaphore

try:
    from art import text2art
except ImportError:
    text2art = None

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import aggregator
    AGGREGATOR_AVAILABLE = True
except ImportError:
    AGGREGATOR_AVAILABLE = False

# cfg
CONFIG_FILE = "config.json"
SOURCES_FILE = "sources.json"

# Стандартные истончники проксей
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
    "local_port_start": 1080, # Отвечает за то, с какого конкретно порта будут запускаться ядра, 1080 > 1081 > 1082 = три потока(три ядра)
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
    url = url.strip()
    url = url.replace('\ufeff', '').replace('\u200b', '')
    url = url.replace('\n', '').replace('\r', '')
    return url

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    
class SmartLogger:
    def __init__(self, filename="checker_history.log"):
        self.filename = filename
        self.lock = Lock()
        try:
            with open(self.filename, 'a', encoding='utf-8') as f:
                f.write(f"\n{'-'*30} NEW SESSION {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {'-'*30}\n")
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

        if '#' in url:
            main_part, tag = url.split('#', 1)
            tag = urllib.parse.unquote(tag).strip()
        else:
            main_part = url
            tag = "vless"

        match = re.search(r'vless://([^@]+)@([^:]+):(\d+)', main_part)
        
        if not match:
            return None

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

        sec = get_p("security", "none")
        pbk_val = get_p("pbk", "")
        
        if pbk_val and sec == "tls":
            sec = "reality"

        return {
            "protocol": "vless",
            "uuid": uuid,
            "address": address,
            "port": port,
            "encryption": get_p("encryption", "none"),
            "type": get_p("type", "tcp"),
            "security": sec,
            "path": urllib.parse.unquote(get_p("path", "")),
            "host": get_p("host", ""),
            "sni": get_p("sni", ""),
            "fp": get_p("fp", ""),
            "alpn": get_p("alpn", ""),
            "serviceName": get_p("serviceName", ""),
            "mode": get_p("mode", ""),
            "pbk": get_p("pbk", ""),
            "sid": get_p("sid", ""),
            "flow": get_p("flow", ""),
            "tag": tag
        }
    except Exception as e:
        safe_print(f"{Fore.RED}[VLESS ERROR] {e}{Style.RESET_ALL}")
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

                return {
                    "protocol": "vmess",
                    "uuid": uuid,
                    "address": address,
                    "port": port,
                    "type": get_p("type", "tcp"),
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
            return {
                "protocol": "vmess",
                "uuid": data.get("id"),
                "address": data.get("add"),
                "port": int(data.get("port", 0)),
                "aid": int(data.get("aid", 0)),
                "type": data.get("net", "tcp"),
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
        
        return {
            "protocol": "trojan",
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": parsed.port,
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
                if ':' not in userinfo:
                    missing_padding = len(userinfo) % 4
                    if missing_padding: userinfo += '=' * (4 - missing_padding)
                    decoded_info = base64.b64decode(userinfo).decode('utf-8')
                else:
                    decoded_info = userinfo
            except:
                decoded_info = userinfo
            
            method, password = decoded_info.split(':', 1)
            address = parsed.hostname
            port = parsed.port
        else:
            b64 = url_clean.replace("ss://", "")
            missing_padding = len(b64) % 4
            if missing_padding: b64 += '=' * (4 - missing_padding)
            decoded = base64.b64decode(b64).decode('utf-8')
            method_pass, addr_port = decoded.rsplit('@', 1)
            method, password = method_pass.split(':', 1)
            address, port = addr_port.rsplit(':', 1)
            port = int(port)

        return {
            "protocol": "shadowsocks",
            "address": address,
            "port": port,
            "method": method,
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
        
        return {
            "protocol": "hysteria2",
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": parsed.port,
            "sni": params.get("sni", [""])[0],
            "insecure": params.get("insecure", ["0"])[0] == "1",
            "obfs": params.get("obfs", ["none"])[0],
            "obfs_password": params.get("obfs-password", [""])[0],
            "tag": urllib.parse.unquote(tag).strip()
        }
    except: return None

def get_proxy_tag(url):
    try:
        url = clean_url(url)
        if '#' in url:
            _, tag = url.rsplit('#', 1)
            return urllib.parse.unquote(tag).strip()
    except: 
        pass
    
    try:
        if url.startswith("vmess"): 
            res = parse_vmess(url)
            if res: return res.get('tag', 'vmess')
    except: pass
    
    return "proxy"

def get_outbound_structure(proxy_url, tag):
    """Преобразует URL в структуру outbound для Xray JSON"""
    proxy_url = clean_url(proxy_url)
    proxy_conf = None
    
    if proxy_url.startswith("vless://"): proxy_conf = parse_vless(proxy_url)
    elif proxy_url.startswith("vmess://"): proxy_conf = parse_vmess(proxy_url)
    elif proxy_url.startswith("trojan://"): proxy_conf = parse_trojan(proxy_url)
    elif proxy_url.startswith("ss://"): proxy_conf = parse_ss(proxy_url)
    elif proxy_url.startswith("hy"): proxy_conf = parse_hysteria2(proxy_url)
    
    if not proxy_conf: return None

    streamSettings = {}
    if proxy_conf["protocol"] in ["vless", "vmess", "trojan"]:
        streamSettings = {
            "network": proxy_conf.get("type", "tcp"),
            "security": proxy_conf.get("security", "none")
        }
        if streamSettings["security"] == "tls":
            streamSettings["tlsSettings"] = {
                "serverName": proxy_conf.get("sni") or proxy_conf.get("host"),
                "allowInsecure": True,
                "fingerprint": proxy_conf.get("fp", "")
            }
        elif streamSettings["security"] == "reality":
             streamSettings["realitySettings"] = {
                "publicKey": proxy_conf.get("pbk"),
                "shortId": proxy_conf.get("sid"),
                "serverName": proxy_conf.get("sni"),
                "fingerprint": proxy_conf.get("fp", "chrome")
            }
        if streamSettings["network"] == "ws":
            streamSettings["wsSettings"] = {
                "path": proxy_conf.get("path", "/"),
                "headers": {"Host": proxy_conf.get("host", "")}
            }
        elif streamSettings["network"] == "grpc":
            streamSettings["grpcSettings"] = {
                "serviceName": proxy_conf.get("serviceName", "") or proxy_conf.get("path", "") or "grpc",
                "multiMode": False
            }

    outbound = {"protocol": proxy_conf["protocol"], "tag": tag, "streamSettings": streamSettings}

    if proxy_conf["protocol"] == "shadowsocks":
        method = proxy_conf["method"].lower()
        if method == "chacha20-ietf": method = "chacha20-ietf-poly1305"
        outbound["settings"] = {"servers": [{"address": proxy_conf["address"], "port": int(proxy_conf["port"]), "method": method, "password": proxy_conf["password"]}]}
        outbound.pop("streamSettings", None)
    elif proxy_conf["protocol"] == "trojan":
        outbound["settings"] = {"servers": [{"address": proxy_conf["address"], "port": int(proxy_conf["port"]), "password": proxy_conf["uuid"]}]}
    elif proxy_conf["protocol"] == "hysteria2":
        hy2_settings = {"address": proxy_conf["address"], "port": int(proxy_conf["port"]), "users": [{"password": proxy_conf["uuid"]}]}
        if proxy_conf.get("obfs") and proxy_conf.get("obfs") != "none":
             hy2_settings["obfs"] = {"type": proxy_conf["obfs"], "password": proxy_conf.get("obfs_password", "")}
        outbound["settings"] = {"vnext": [hy2_settings]}
        outbound["streamSettings"] = {"security": "tls", "tlsSettings": {"serverName": proxy_conf.get("sni", ""), "allowInsecure": proxy_conf.get("insecure", False)}}
    else:
        outbound["settings"] = {"vnext": [{
            "address": proxy_conf["address"], "port": int(proxy_conf["port"]),
            "users": [{"id": proxy_conf["uuid"], "alterId": proxy_conf.get("aid", 0), "encryption": "none", "flow": proxy_conf.get("flow", "")}]
        }]}
    return outbound

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
        if not out_struct: continue
        
        inbounds.append({
            "port": port, "listen": "127.0.0.1", "protocol": "socks",
            "tag": in_tag, "settings": {"udp": True}
        })
        outbounds.append(out_struct)
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})
        valid_proxies.append((url, port))

    if not outbounds: return None, None, "No valid proxies"

    full_config = {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules}
    }

    config_path = os.path.join(work_dir, f"batch_{start_port}.json")
    with open(config_path, 'w') as f:
        json.dump(full_config, f, indent=2)
    
    return config_path, valid_proxies, None

def run_core(core_path, config_path):
    cmd = [core_path, "run", "-c", config_path] if "xray" in core_path.lower() else [core_path, "-c", config_path]
    startupinfo = None
    if OS_SYSTEM == "windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, startupinfo=startupinfo)
    except: return None

def kill_core(proc):
    if not proc: return
    try:
        if psutil:
            parent = psutil.Process(proc.pid)
            for child in parent.children(recursive=True):
                try: child.kill() 
                except: pass
            parent.kill()
        else:
            proc.terminate()
            try: proc.wait(timeout=0.2)
            except: proc.kill()
    except: pass

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
        return current_live_results

    if not wait_for_core_start(valid_mapping[0][1], t2exec):
        kill_core(proc)
        return current_live_results

    def check_single_port(item):
        if CTRL_C: return None
        target_url, target_port = item
        proxy_tag = get_proxy_tag(target_url)
        
        ping_res, error_reason = check_connection(target_port, testDomain, timeOut)
        
        proxy_speed = 0.0
        if ping_res:
            if checkSpeed:
                with (speedSemaphore if speedSemaphore else Lock()):
                    proxy_speed = check_speed_download(target_port, speedUrl, **speedCfg)
                sp_color = "green" if proxy_speed > 15 else "yellow" if proxy_speed > 5 else "red"
                safe_print(f"[green][LIVE][/] {ping_res}ms | [{sp_color}]{proxy_speed} Mbps[/] | {proxy_tag}")
            else:
                safe_print(f"[green][LIVE][/] {ping_res}ms | {proxy_tag}")
            
            if progress and task_id is not None:
                progress.advance(task_id, 1)
            return (target_url, ping_res, proxy_speed)
        
        else:
            short_err = str(error_reason)
            if "Read timed out" in short_err: short_err = "Timeout"
            elif "Connection aborted" in short_err: short_err = "Conn Aborted"
            safe_print(f"[yellow][Dead][/] {proxy_tag[:15]}.. -> [dim]{short_err}[/]")
            
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
    
    CORE_PATH = shutil.which(args.core)
    if not CORE_PATH:
        candidates = ["xray.exe", "xray", "v2ray.exe", "v2ray", "bin/xray.exe", "bin/xray"]
        for c in candidates:
             if os.path.exists(c):
                 CORE_PATH = os.path.abspath(c)
                 break
    
    if not CORE_PATH:
        safe_print(f"[bold red]\n[ERROR] Ядро (xray/v2ray) не найдено![/]")
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
        title=f"[bold magenta]MK_XRAYchecker[/] [dim](font: {font_name})[/]",
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
    console.print("[yellow]>> Поиск и принудительная остановка процессов ядра...[/]")
    killed_count = 0
    target_names = ["xray.exe", "v2ray.exe", "xray", "v2ray", "wxray.exe", "wxray"]
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in target_names:
                proc.kill()
                killed_count += 1
        except: pass
    
    if killed_count > 0:
        console.print(f"[bold green]>> Успешно убито {killed_count} зависших процессов.[/]")
    else:
        console.print("[dim]>> Активных процессов ядра не найдено.[/]")
    time.sleep(1.5)

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
        table.add_row("0", "Выход", "Закрыть программу")
        
        console.print(table)
        
        valid_choices = ["0", "1", "2", "3", "4", "5"] if AGGREGATOR_AVAILABLE else ["0", "1", "2", "3", "5"]
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
            traceback.print_exc()
        
        Prompt.ask("\n[bold]Нажмите Enter чтобы вернуться в меню...[/]", password=False)

def main():
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

    if len(sys.argv) == 1:
        interactive_menu()
    else:
        args = parser.parse_args()
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