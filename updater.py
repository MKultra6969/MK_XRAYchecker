# +═════════════════════════════════════════════════════════════════════════+
# ║                                 UPDATER                                 ║
# ║                   Модуль самообновления v2rayChecker                    ║
# +═════════════════════════════════════════════════════════════════════════+
# ║                               by MKultra69                              ║
# +═════════════════════════════════════════════════════════════════════════+


import os
import re
import sys
import json
import hashlib
import subprocess
import requests
from datetime import datetime, timedelta

# ═══════════════════════════════════════════════════════════════════════════
# ВЕРСИЯ И КОНФИГУРАЦИЯ
# Эта версия используется для сравнения с GitHub releases
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "1.9.0"

# Настройки репо по умолчанию (можно переопределить через config.json)
DEFAULT_REPO = {
    "owner": "MKultra6969",
    "repo": "MK_XRAYchecker",
    "branch": "main"
}

# Файлы, которые будем обновлять
# Формат: (имя_файла, обязательный)
MANAGED_FILES = [
    ("v2rayChecker.py", True),    # обязательный
    ("aggregator.py", False),     # опциональный
    ("mtproto_checker.py", True), # обязательный
    ("mtproto_faketls.py", True), # обязательный
    ("updater.py", True),         # обязательный
    ("xray_installer.py", True),  # обязательный
    ("requirements.txt", True)    # обязательный (для совместимости зависимостей)
]

PENDING_MARKER = "update.pending"
FAILED_MARKER = "update.failed"
BACKUP_SUFFIX = ".bak"
PIP_TIMEOUT_SEC = 600
SMOKE_TIMEOUT_SEC = 120

# ═══════════════════════════════════════════════════════════════════════════
# АВТООБНОВЛЕНИЕ ЯДЕР (Telethon / Xray / Mihomo)
# ═══════════════════════════════════════════════════════════════════════════
CORE_UPDATE_STATE_FILE = "core_update.state.json"
TELETHON_PYPI_URL = "https://pypi.org/pypi/Telethon/json"
TELETHON_PACKAGE = "telethon"

# Telethon 2.x - это полный rewrite с несовместимым API, mtproto_checker/
# mtproto_faketls рассчитаны на ветку 1.x. Поэтому апгрейд по умолчанию
# ограничен сверху; снять ограничение можно пустой строкой в конфиге.
DEFAULT_TELETHON_MAX_VERSION = "2.0.0"

CORE_UPDATE_TARGETS = ("telethon", "xray", "mihomo")

DEFAULT_CORE_AUTOUPDATE = {
    "enabled": True,
    "auto_apply": True,
    "check_interval_hours": 24,
    "telethon": True,
    "xray": True,
    "mihomo": True,
    "telethon_max_version": DEFAULT_TELETHON_MAX_VERSION,
}

def _get_script_dir():
    return os.path.dirname(os.path.abspath(__file__))

def _safe_print(msg, style=None):
    try:
        from rich.console import Console
        console = Console()
        console.print(msg, style=style)
        return
    except Exception:
        pass

    try:
        import re
        clean_msg = re.sub(r'\[.*?\]', '', str(msg))
        try:
            print(clean_msg)
        except UnicodeEncodeError:
            enc = getattr(sys.stdout, "encoding", None) or "utf-8"
            safe_msg = clean_msg.encode(enc, errors="replace").decode(enc, errors="replace")
            print(safe_msg)
    except Exception:
        pass

def _parse_version(version_str):
    v = version_str.strip().lstrip('vV')
    
    parts = v.split('.')
    
    result = []
    for i in range(3):
        if i < len(parts):
            try:
                result.append(int(parts[i].split('-')[0]))
            except ValueError:
                result.append(0)
        else:
            result.append(0)
    
    return tuple(result)

def _is_newer_version(current, remote):

    current_tuple = _parse_version(current)
    remote_tuple = _parse_version(remote)
    return remote_tuple > current_tuple

def _file_hash(filepath):

    if not os.path.exists(filepath):
        return None
    
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def get_latest_script_version(cfg):

    owner = cfg.get("repo_owner", DEFAULT_REPO["owner"])
    repo = cfg.get("repo_name", DEFAULT_REPO["repo"])
    branch = cfg.get("repo_branch", DEFAULT_REPO["branch"])
    
    api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    raw_base = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/"
    
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": f"v2rayChecker-Updater/{__version__}"
    }
    
    try:
        _safe_print(f"[dim]Проверка обновлений: {owner}/{repo}...[/]")
        
        resp = requests.get(api_url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            tag_name = data.get("tag_name", "")
            version = tag_name.lstrip('v')
            
            version_info = {
                "version": version,
                "tag_name": tag_name,
                "raw_base_url": raw_base,
                "release_url": data.get("html_url", ""),
                "published_at": data.get("published_at", ""),
                "body": data.get("body", "")[:500],
            }
            
            _safe_print(f"[dim]Последняя версия в релизах: {version}[/]")
            return version, version_info
            
        elif resp.status_code == 404:
            _safe_print("[dim]Релизы не найдены, проверяем VERSION файл...[/]")
        else:
            _safe_print(f"[yellow]GitHub API вернул {resp.status_code}[/]")
            
    except requests.exceptions.Timeout:
        _safe_print("[yellow]Таймаут при обращении к GitHub API[/]")
    except requests.exceptions.RequestException as e:
        _safe_print(f"[yellow]Ошибка сети: {e}[/]")
    except Exception as e:
        _safe_print(f"[yellow]Ошибка при проверке релизов: {e}[/]")
    
    try:
        version_url = f"{raw_base}VERSION"
        resp = requests.get(version_url, timeout=10, headers={"User-Agent": "v2rayChecker"})
        
        if resp.status_code == 200:
            version = resp.text.strip().lstrip('v')
            version_info = {
                "version": version,
                "tag_name": f"v{version}",
                "raw_base_url": raw_base,
            }
            _safe_print(f"[dim]Версия из VERSION файла: {version}[/]")
            return version, version_info
            
    except Exception as e:
        _safe_print(f"[dim]Не удалось прочитать VERSION: {e}[/]")
    
    return None, None

def download_script_files(version_info, cfg):

    if not version_info:
        return None
    
    raw_base = version_info.get("raw_base_url")
    if not raw_base:
        return None
    
    script_dir = _get_script_dir()
    downloaded = {}
    
    for filename, required in MANAGED_FILES:
        url = f"{raw_base}{filename}"
        local_path = os.path.join(script_dir, filename)
        
        try:
            _safe_print(f"[dim]Скачивание: {filename}...[/]")
            
            resp = requests.get(url, timeout=30, headers={"User-Agent": "v2rayChecker"})
            
            if resp.status_code == 200:
                content = resp.content
                
                local_hash = _file_hash(local_path)
                remote_hash = hashlib.sha256(content).hexdigest()
                
                if local_hash != remote_hash:
                    downloaded[filename] = content
                    _safe_print(f"[green]✓ {filename}: изменён, будет обновлён[/]")
                else:
                    _safe_print(f"[dim]✓ {filename}: без изменений[/]")
                    
            elif resp.status_code == 404 and not required:
                _safe_print(f"[dim]- {filename}: не найден в репо (опциональный)[/]")
            else:
                _safe_print(f"[yellow]! {filename}: HTTP {resp.status_code}[/]")
                if required:
                    return None
                    
        except Exception as e:
            _safe_print(f"[red]Ошибка скачивания {filename}: {e}[/]")
            if required:
                return None
    
    return downloaded if downloaded else None

def stage_update(files, version_info):

    if not files:
        return False
    
    script_dir = _get_script_dir()
    staged_files = []
    
    try:
        for filename, content in files.items():
            new_path = os.path.join(script_dir, f"{filename}.new")
            
            with open(new_path, 'wb') as f:
                f.write(content)
            
            staged_files.append(filename)
            _safe_print(f"[dim]Staged: {filename}.new[/]")
        
        pending_info = {
            "version": version_info.get("version", "unknown"),
            "staged_at": datetime.now().isoformat(),
            "files": staged_files,
            "release_url": version_info.get("release_url", ""),
        }
        
        marker_path = os.path.join(script_dir, PENDING_MARKER)
        with open(marker_path, 'w', encoding='utf-8') as f:
            json.dump(pending_info, f, indent=2)
        
        _safe_print(f"[green]✓ Обновление staged ({len(staged_files)} файлов)[/]")
        return True
        
    except Exception as e:
        _safe_print(f"[red]Ошибка staging: {e}[/]")
        
        for filename in staged_files:
            try:
                os.remove(os.path.join(script_dir, f"{filename}.new"))
            except:
                pass
        
        return False

def _cleanup_staged_files(script_dir, files):
    for filename in files or []:
        try:
            new_path = os.path.join(script_dir, f"{filename}.new")
            if os.path.exists(new_path):
                os.remove(new_path)
        except Exception:
            pass

def _cleanup_backups(script_dir, files):
    for filename in files or []:
        try:
            backup_path = os.path.join(script_dir, f"{filename}{BACKUP_SUFFIX}")
            if os.path.exists(backup_path):
                os.remove(backup_path)
        except Exception:
            pass

def _rollback_applied_files(script_dir, applied_files):
    for filename in reversed(applied_files or []):
        backup_path = os.path.join(script_dir, f"{filename}{BACKUP_SUFFIX}")
        target_path = os.path.join(script_dir, filename)
        if not os.path.exists(backup_path):
            continue
        try:
            if os.path.exists(target_path):
                os.remove(target_path)
            os.replace(backup_path, target_path)
            _safe_print(f"[yellow][UPDATER] ROLLBACK: {filename}[/]")
        except Exception as e:
            _safe_print(f"[red][UPDATER] ROLLBACK ERROR {filename}: {e}[/]")

def _install_requirements_if_present(script_dir):
    req_path = os.path.join(script_dir, "requirements.txt")
    if not os.path.exists(req_path):
        return True, "requirements.txt not found"

    cmd = [
        sys.executable, "-m", "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "-r", req_path
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PIP_TIMEOUT_SEC,
            cwd=script_dir
        )
        if result.returncode == 0:
            return True, "ok"
        err_tail = (result.stderr or result.stdout or "").strip()[-1200:]
        return False, err_tail or "pip install failed"
    except Exception as e:
        return False, str(e)

def _smoke_check_startup(script_dir):
    checker_path = os.path.join(script_dir, "v2rayChecker.py")
    if not os.path.exists(checker_path):
        return False, "v2rayChecker.py not found"
    mtproto_path = os.path.join(script_dir, "mtproto_checker.py")
    if not os.path.exists(mtproto_path):
        return False, "mtproto_checker.py not found"
    mtproto_faketls_path = os.path.join(script_dir, "mtproto_faketls.py")
    if not os.path.exists(mtproto_faketls_path):
        return False, "mtproto_faketls.py not found"

    try:
        compile_cmd = [sys.executable, "-m", "py_compile", checker_path, mtproto_path, mtproto_faketls_path]
        comp = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            timeout=SMOKE_TIMEOUT_SEC,
            cwd=script_dir
        )
        if comp.returncode != 0:
            tail = (comp.stderr or comp.stdout or "").strip()[-1500:]
            return False, tail or "py_compile failed"

        smoke_code = (
            "import requests, psutil, urllib3, rich, telethon\n"
            "import updater, xray_installer, mtproto_checker, mtproto_faketls\n"
            "assert getattr(mtproto_checker, 'TELETHON_AVAILABLE', False), "
            "getattr(mtproto_checker, 'TELETHON_IMPORT_ERROR', 'telethon unavailable')\n"
            "print('smoke-ok')\n"
        )
        import_cmd = [sys.executable, "-c", smoke_code]
        imp = subprocess.run(
            import_cmd,
            capture_output=True,
            text=True,
            timeout=SMOKE_TIMEOUT_SEC,
            cwd=script_dir
        )
        if imp.returncode != 0:
            tail = (imp.stderr or imp.stdout or "").strip()[-1500:]
            return False, tail or "import smoke failed"

        return True, "ok"
    except Exception as e:
        return False, str(e)

def _write_failed_marker(script_dir, pending_info, reason, details):
    payload = {
        "failed_at": datetime.now().isoformat(),
        "version": pending_info.get("version", "unknown"),
        "files": pending_info.get("files", []),
        "reason": reason,
        "details": (details or "")[-4000:]
    }
    try:
        with open(os.path.join(script_dir, FAILED_MARKER), "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def apply_pending_update_if_any():
    script_dir = _get_script_dir()
    marker_path = os.path.join(script_dir, PENDING_MARKER)
    
    if not os.path.exists(marker_path):
        return False
    
    try:
        with open(marker_path, 'r', encoding='utf-8') as f:
            pending_info = json.load(f)
        
        files = pending_info.get("files", [])
        version = pending_info.get("version", "unknown")
        
        if not files:
            os.remove(marker_path)
            return False
        
        _safe_print(f"[bold cyan][UPDATER][/]: Применение обновления до версии {version}...")

        missing_new = []
        for filename in files:
            new_path = os.path.join(script_dir, f"{filename}.new")
            if not os.path.exists(new_path):
                missing_new.append(filename)

        if missing_new:
            _safe_print(f"[red][UPDATER] Не найдены staged-файлы: {missing_new}[/]")
            _rollback_applied_files(script_dir, files)
            _cleanup_backups(script_dir, files)
            _write_failed_marker(script_dir, pending_info, "missing_staged_files", "\n".join(missing_new))
            _cleanup_staged_files(script_dir, files)
            try:
                os.remove(marker_path)
            except Exception:
                pass
            return False

        applied = []
        try:
            for filename in files:
                new_path = os.path.join(script_dir, f"{filename}.new")
                target_path = os.path.join(script_dir, filename)
                backup_path = os.path.join(script_dir, f"{filename}{BACKUP_SUFFIX}")

                if os.path.exists(target_path):
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                    os.replace(target_path, backup_path)

                os.replace(new_path, target_path)
                applied.append(filename)
                _safe_print(f"[green][UPDATER] Обновлён: {filename}[/]")
        except Exception as e:
            _safe_print(f"[red][UPDATER] Ошибка применения staged-файлов: {e}[/]")
            _rollback_applied_files(script_dir, applied)
            _write_failed_marker(script_dir, pending_info, "apply_failed", str(e))
            _cleanup_staged_files(script_dir, files)
            try:
                os.remove(marker_path)
            except Exception:
                pass
            return False

        dep_ok, dep_msg = _install_requirements_if_present(script_dir)
        if dep_ok:
            _safe_print("[green][UPDATER] Зависимости проверены/установлены[/]")
        else:
            _safe_print(f"[yellow][UPDATER] pip install завершился с ошибкой: {dep_msg}[/]")

        smoke_ok, smoke_msg = _smoke_check_startup(script_dir)
        if not smoke_ok:
            _safe_print(f"[red][UPDATER] Smoke-check не пройден: {smoke_msg}[/]")
            _rollback_applied_files(script_dir, applied)
            _write_failed_marker(script_dir, pending_info, "smoke_check_failed", smoke_msg)
            _cleanup_staged_files(script_dir, files)
            _cleanup_backups(script_dir, files)
            try:
                os.remove(marker_path)
            except Exception:
                pass
            return False

        _cleanup_backups(script_dir, files)
        _cleanup_staged_files(script_dir, files)
        try:
            os.remove(marker_path)
        except Exception:
            pass
        try:
            failed_marker = os.path.join(script_dir, FAILED_MARKER)
            if os.path.exists(failed_marker):
                os.remove(failed_marker)
        except Exception:
            pass

        _safe_print(f"[bold green][UPDATER] Обновление завершено ({len(applied)} файлов)[/]")
        if not dep_ok:
            _safe_print("[yellow][UPDATER] Внимание: зависимости не все установились, но стартовая проверка пройдена[/]")
        return True
        
    except Exception as e:
        _safe_print(f"[red][UPDATER] Ошибка при применении обновления: {e}[/]")
        
        try:
            os.remove(marker_path)
        except:
            pass
        
        return False

def maybe_self_update(cfg):
    if "--no-update" in sys.argv or os.environ.get("MKXRAY_SKIP_SELF_UPDATE") == "1":
        _safe_print("[dim]Проверка обновлений пропущена (--no-update)[/]")
        return

    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "v2rayChecker_version", 
            os.path.join(_get_script_dir(), "v2rayChecker.py")
        )
        with open(os.path.join(_get_script_dir(), "v2rayChecker.py"), 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith("__version__"):
                    current_version = line.split("=")[1].strip().strip('"\'')
                    break
            else:
                current_version = "0.0.0"
    except:
        current_version = __version__
    
    remote_version, version_info = get_latest_script_version(cfg)
    
    if not remote_version or not version_info:
        return
    
    if not _is_newer_version(current_version, remote_version):
        _safe_print(f"[dim]Версия актуальна: {current_version}[/]")
        return
    
    _safe_print(f"[bold yellow]Доступно обновление: {current_version} → {remote_version}[/]")
    
    autoupdate = cfg.get("autoupdate", False)
    
    if not autoupdate:
        try:
            from rich.prompt import Confirm
            should_update = Confirm.ask(
                f"[bold cyan]Обновить скрипт?[/]",
                default=True
            )
        except ImportError:
            response = input(f"Обновить скрипт до версии {remote_version}? [Y/n]: ").strip().lower()
            should_update = response in ('', 'y', 'yes', 'д', 'да')
        
        if not should_update:
            _safe_print("[dim]Обновление отменено пользователем[/]")
            return
    else:
        _safe_print("[dim]Автообновление включено, скачиваем...[/]")
    
    files = download_script_files(version_info, cfg)
    
    if not files:
        _safe_print("[yellow]Нет файлов для обновления (возможно, уже актуальны)[/]")
        return
    
    if not stage_update(files, version_info):
        _safe_print("[red]Не удалось подготовить обновление[/]")
        return
    
    _safe_print("[bold green]Обновление готово! Перезапуск скрипта...[/]")
    
    try:
        import time
        time.sleep(1)
        
        os.execv(sys.executable, [sys.executable] + sys.argv)
        
    except Exception as e:
        _safe_print(f"[yellow]Не удалось перезапуститься автоматически: {e}[/]")
        _safe_print("[bold]Пожалуйста, перезапустите скрипт вручную для применения обновлений.[/]")

def get_current_version():
    return __version__


# ═══════════════════════════════════════════════════════════════════════════
# АВТООБНОВЛЕНИЕ ЯДЕР: конфиг и состояние
# ═══════════════════════════════════════════════════════════════════════════

def _as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on", "y", "да"):
        return True
    if text in ("0", "false", "no", "off", "n", "нет"):
        return False
    return default


def get_core_autoupdate_cfg(cfg):
    """Нормализует блок core_autoupdate из config.json, добивая дефолтами."""
    opts = dict(DEFAULT_CORE_AUTOUPDATE)

    raw = (cfg or {}).get("core_autoupdate")
    if not isinstance(raw, dict):
        return opts

    for key in ("enabled", "auto_apply", "telethon", "xray", "mihomo"):
        if key in raw:
            opts[key] = _as_bool(raw.get(key), DEFAULT_CORE_AUTOUPDATE[key])

    if "check_interval_hours" in raw:
        try:
            opts["check_interval_hours"] = max(0, int(raw.get("check_interval_hours")))
        except (TypeError, ValueError):
            pass

    if "telethon_max_version" in raw:
        opts["telethon_max_version"] = str(raw.get("telethon_max_version") or "").strip()

    return opts


def _core_state_path():
    return os.path.join(_get_script_dir(), CORE_UPDATE_STATE_FILE)


def load_core_update_state():
    path = _core_state_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_core_update_state(state):
    try:
        with open(_core_state_path(), "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def _should_check_cores(state, interval_hours, force=False):
    if force or interval_hours <= 0:
        return True

    last_check = (state or {}).get("last_check")
    if not last_check:
        return True

    try:
        last_dt = datetime.fromisoformat(str(last_check))
    except (TypeError, ValueError):
        return True

    return datetime.now() - last_dt >= timedelta(hours=interval_hours)


def _confirm_core_update(question, default=True):
    """Спрашивает пользователя, если есть интерактивный stdin; иначе - отказ."""
    try:
        if not sys.stdin or not sys.stdin.isatty():
            return False
    except Exception:
        return False

    try:
        from rich.prompt import Confirm
        return Confirm.ask(question, default=default)
    except ImportError:
        pass
    except Exception:
        return False

    try:
        import re as _re
        plain = _re.sub(r'\[.*?\]', '', question)
        suffix = "[Y/n]" if default else "[y/N]"
        response = input(f"{plain} {suffix}: ").strip().lower()
        if not response:
            return default
        return response in ('y', 'yes', 'д', 'да')
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════
# TELETHON
# ═══════════════════════════════════════════════════════════════════════════

def get_installed_telethon_version():
    try:
        from importlib import metadata as importlib_metadata
    except ImportError:
        importlib_metadata = None

    if importlib_metadata is not None:
        for dist_name in ("Telethon", "telethon"):
            try:
                return importlib_metadata.version(dist_name)
            except Exception:
                continue

    try:
        import telethon
        return getattr(telethon, "__version__", None)
    except Exception:
        return None


def _is_prerelease_version(version_str):
    return bool(re.search(r'[A-Za-z]', str(version_str or "").strip().lstrip('vV')))


def get_latest_telethon_version(max_version=DEFAULT_TELETHON_MAX_VERSION):
    """
    Возвращает последнюю stable-версию Telethon с PyPI.

    max_version - строгая верхняя граница (например "2.0.0"), чтобы не улететь
    на несовместимую мажорную ветку. Пустая строка снимает ограничение.
    """
    try:
        _safe_print("[dim]Проверка последней версии Telethon (PyPI)...[/]")
        resp = requests.get(
            TELETHON_PYPI_URL,
            timeout=15,
            headers={"User-Agent": f"v2rayChecker-Updater/{__version__}"}
        )
        if resp.status_code != 200:
            _safe_print(f"[yellow]PyPI вернул {resp.status_code}[/]")
            return None
        data = resp.json()
    except requests.exceptions.Timeout:
        _safe_print("[yellow]Таймаут при обращении к PyPI[/]")
        return None
    except requests.exceptions.RequestException as e:
        _safe_print(f"[yellow]Ошибка сети (PyPI): {e}[/]")
        return None
    except Exception as e:
        _safe_print(f"[yellow]Ошибка при проверке версии Telethon: {e}[/]")
        return None

    latest = str((data.get("info") or {}).get("version", "")).strip()
    bound = _parse_version(max_version) if max_version else None

    if not bound:
        return latest or None

    if latest and not _is_prerelease_version(latest) and _parse_version(latest) < bound:
        return latest

    # latest вышел за границу - ищем максимальную версию под ней
    best_version = None
    best_tuple = None
    for version, files in (data.get("releases") or {}).items():
        if not files:
            continue
        if all(f.get("yanked") for f in files):
            continue
        if _is_prerelease_version(version):
            continue

        parsed = _parse_version(version)
        if parsed >= bound:
            continue
        if best_tuple is None or parsed > best_tuple:
            best_tuple = parsed
            best_version = version

    if best_version:
        _safe_print(
            f"[dim]Telethon {latest} за пределами разрешённой ветки (< {max_version}), "
            f"берём {best_version}[/]"
        )
    return best_version


def _verify_telethon_runtime():
    """Проверяет, что после установки Telethon импортируется вместе с MTProto-модулями."""
    script_dir = _get_script_dir()
    code = (
        "import telethon\n"
        "import mtproto_faketls, mtproto_checker\n"
        "assert getattr(mtproto_checker, 'TELETHON_AVAILABLE', False), "
        "getattr(mtproto_checker, 'TELETHON_IMPORT_ERROR', 'telethon unavailable')\n"
        "print('telethon-ok')\n"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=SMOKE_TIMEOUT_SEC,
            cwd=script_dir
        )
        if result.returncode == 0:
            return True, "ok"
        tail = (result.stderr or result.stdout or "").strip()[-1500:]
        return False, tail or "telethon import check failed"
    except Exception as e:
        return False, str(e)


def _pip_install(spec, force_reinstall=False):
    cmd = [
        sys.executable, "-m", "pip", "install",
        "--disable-pip-version-check",
        "--no-input",
        "--upgrade",
    ]
    if force_reinstall:
        cmd.append("--force-reinstall")
    cmd.append(spec)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PIP_TIMEOUT_SEC,
            cwd=_get_script_dir()
        )
        if result.returncode == 0:
            return True, "ok"
        tail = (result.stderr or result.stdout or "").strip()[-1500:]
        return False, tail or "pip install failed"
    except Exception as e:
        return False, str(e)


def check_telethon_update(opts=None):
    """Возвращает dict: core, installed, latest, needs_update, error."""
    opts = opts or DEFAULT_CORE_AUTOUPDATE
    result = {
        "core": "telethon",
        "installed": None,
        "latest": None,
        "needs_update": False,
        "error": None,
    }

    installed = get_installed_telethon_version()
    result["installed"] = installed

    if not installed:
        result["error"] = "Telethon не установлен"
        return result

    latest = get_latest_telethon_version(opts.get("telethon_max_version", DEFAULT_TELETHON_MAX_VERSION))
    result["latest"] = latest

    if not latest:
        result["error"] = "не удалось получить версию Telethon с PyPI"
        return result

    result["needs_update"] = _is_newer_version(installed, latest)
    return result


def update_telethon(target_version=None, previous_version=None):
    """
    Ставит Telethon нужной версии через pip и проверяет импорт.
    При провале проверки откатывается на previous_version.

    Возвращает dict: core, updated, installed, latest, rolled_back, error
    """
    result = {
        "core": "telethon",
        "updated": False,
        "installed": previous_version or get_installed_telethon_version(),
        "latest": target_version,
        "rolled_back": False,
        "error": None,
    }

    previous_version = result["installed"]
    spec = f"{TELETHON_PACKAGE}=={target_version}" if target_version else TELETHON_PACKAGE

    _safe_print(f"[cyan]Обновление Telethon: {previous_version or '?'} → {target_version or 'latest'}...[/]")

    ok, msg = _pip_install(spec)
    if not ok:
        result["error"] = f"pip install failed: {msg}"
        return result

    verified, verify_msg = _verify_telethon_runtime()
    if not verified:
        _safe_print(f"[red]Telethon после обновления не проходит проверку импорта: {verify_msg}[/]")
        if previous_version:
            _safe_print(f"[yellow]ROLLBACK: возвращаем Telethon {previous_version}[/]")
            back_ok, back_msg = _pip_install(f"{TELETHON_PACKAGE}=={previous_version}", force_reinstall=True)
            result["rolled_back"] = back_ok
            if not back_ok:
                _safe_print(f"[red]Откат Telethon не удался: {back_msg}[/]")
        result["error"] = f"проверка импорта не пройдена: {verify_msg}"
        return result

    result["updated"] = True
    result["latest"] = get_installed_telethon_version() or target_version
    return result


# ═══════════════════════════════════════════════════════════════════════════
# ОРКЕСТРАТОР: Telethon + Xray + Mihomo
# ═══════════════════════════════════════════════════════════════════════════

def _get_xray_installer():
    try:
        import xray_installer
    except ImportError as e:
        _safe_print(f"[yellow]xray_installer недоступен: {e}[/]")
        return None

    if not hasattr(xray_installer, "check_for_core_update"):
        _safe_print("[yellow]Текущая версия xray_installer.py не умеет обновлять ядра[/]")
        return None

    return xray_installer


def check_cores_status(cfg, targets=None):
    """
    Проверяет версии всех ядер без установки обновлений.
    Возвращает список dict'ов (по одному на ядро).
    """
    opts = get_core_autoupdate_cfg(cfg)
    targets = targets or CORE_UPDATE_TARGETS
    statuses = []

    for target in targets:
        if target == "telethon":
            statuses.append(check_telethon_update(opts))
            continue

        installer = _get_xray_installer()
        if not installer:
            statuses.append({
                "core": target, "installed": None, "latest": None,
                "needs_update": False, "error": "xray_installer недоступен",
            })
            continue

        statuses.append(installer.check_for_core_update(target, cfg=cfg))

    return statuses


def _apply_core_update(target, cfg, status, opts):
    label = {"telethon": "Telethon", "xray": "Xray", "mihomo": "Mihomo"}.get(target, target)
    installed = status.get("installed")
    latest = status.get("latest")

    _safe_print(f"[bold yellow]Доступно обновление {label}: {installed} → {latest}[/]")

    if not opts.get("auto_apply", True):
        if not _confirm_core_update(f"[bold cyan]Обновить {label} до {latest}?[/]", default=True):
            _safe_print(f"[dim]Обновление {label} пропущено[/]")
            return dict(status, updated=False, skipped="declined")

    if target == "telethon":
        return update_telethon(target_version=latest, previous_version=installed)

    installer = _get_xray_installer()
    if not installer:
        return dict(status, updated=False, error="xray_installer недоступен")

    return installer.update_core_binary(
        target,
        cfg=cfg,
        release_info=status.get("release"),
        core_path=status.get("path"),
    )


def maybe_update_cores(cfg, force=False, targets=None):
    """
    Точка входа автообновления ядер (Telethon / Xray / Mihomo).

    force=True - игнорировать мастер-выключатель и интервал (ручной запуск из меню).

    Возвращает dict:
      checked, skipped, results, updated, restart_required
    """
    summary = {
        "checked": False,
        "skipped": None,
        "results": [],
        "updated": [],
        "restart_required": False,
    }

    opts = get_core_autoupdate_cfg(cfg)

    if not force and not opts.get("enabled", True):
        summary["skipped"] = "disabled"
        return summary

    state = load_core_update_state()

    if not _should_check_cores(state, opts.get("check_interval_hours", 24), force=force):
        summary["skipped"] = "throttled"
        return summary

    # force снимает мастер-выключатель и интервал, но per-core тумблеры уважаются
    if targets is None:
        targets = [t for t in CORE_UPDATE_TARGETS if opts.get(t, True)]

    if not targets:
        summary["skipped"] = "no_targets"
        return summary

    summary["checked"] = True
    _safe_print("[dim]Проверка обновлений ядер (Telethon/Xray/Mihomo)...[/]")

    for target in targets:
        try:
            if target == "telethon":
                status = check_telethon_update(opts)
            else:
                installer = _get_xray_installer()
                if not installer:
                    continue
                status = installer.check_for_core_update(target, cfg=cfg)
        except Exception as e:
            _safe_print(f"[yellow]Ошибка проверки {target}: {e}[/]")
            summary["results"].append({"core": target, "error": str(e), "updated": False})
            continue

        if status.get("error"):
            _safe_print(f"[dim]{target}: {status['error']}[/]")
            summary["results"].append(dict(status, updated=False))
            continue

        if not status.get("needs_update"):
            _safe_print(f"[dim]{target}: версия актуальна ({status.get('installed')})[/]")
            summary["results"].append(dict(status, updated=False))
            continue

        try:
            applied = _apply_core_update(target, cfg, status, opts)
        except Exception as e:
            _safe_print(f"[red]Ошибка обновления {target}: {e}[/]")
            applied = dict(status, updated=False, error=str(e))

        summary["results"].append(applied)

        if applied.get("updated"):
            summary["updated"].append(target)
            _safe_print(
                f"[bold green]✓ {target} обновлён: "
                f"{applied.get('installed')} → {applied.get('latest')}[/]"
            )
            if target == "telethon":
                summary["restart_required"] = True

    state["last_check"] = datetime.now().isoformat()
    state["versions"] = {
        item.get("core"): (item.get("latest") if item.get("updated") else item.get("installed"))
        for item in summary["results"] if item.get("core")
    }
    save_core_update_state(state)

    return summary


if __name__ == "__main__":
    print(f"Updater module version: {__version__}")
    print(f"Script directory: {_get_script_dir()}")
    
    test_versions = [
        ("1.0.0", "1.0.1", True),
        ("1.0.0", "1.0.0", False),
        ("1.0.0", "0.9.9", False),
        ("1.4.1", "2.0.0", True),
        ("v1.0.0", "1.0.1", True),
    ]
    
    print("\nVersion comparison test:")
    for current, remote, expected in test_versions:
        result = _is_newer_version(current, remote)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {current} vs {remote}: {result} (expected {expected})")
