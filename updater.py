# +═════════════════════════════════════════════════════════════════════════+
# ║                                 UPDATER                                 ║
# ║                   Модуль самообновления v2rayChecker                    ║
# +═════════════════════════════════════════════════════════════════════════+
# ║                               by MKultra69                              ║
# +═════════════════════════════════════════════════════════════════════════+


import os
import sys
import json
import hashlib
import subprocess
import requests
from datetime import datetime

# ═══════════════════════════════════════════════════════════════════════════
# ВЕРСИЯ И КОНФИГУРАЦИЯ
# Эта версия используется для сравнения с GitHub releases
# ═══════════════════════════════════════════════════════════════════════════
__version__ = "1.1.3"

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
    ("updater.py", True),         # обязательный
    ("xray_installer.py", True),  # обязательный
    ("requirements.txt", True)    # обязательный (для совместимости зависимостей)
]

PENDING_MARKER = "update.pending"
FAILED_MARKER = "update.failed"
BACKUP_SUFFIX = ".bak"
PIP_TIMEOUT_SEC = 600
SMOKE_TIMEOUT_SEC = 120

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

    try:
        compile_cmd = [sys.executable, "-m", "py_compile", checker_path]
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
            "import requests, psutil, urllib3, rich\n"
            "import updater, xray_installer\n"
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

        # Сначала проверяем, что все staged-файлы на месте.
        missing_new = []
        for filename in files:
            new_path = os.path.join(script_dir, f"{filename}.new")
            if not os.path.exists(new_path):
                missing_new.append(filename)

        if missing_new:
            _safe_print(f"[red][UPDATER] Не найдены staged-файлы: {missing_new}[/]")
            # Возможный кейс: прошлый apply был прерван. Пытаемся восстановить из backup.
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

        # После замены файлов: устанавливаем зависимости и делаем smoke-check.
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

        # Если smoke-check успешен, даже при проблемах pip не откатываем:
        # скрипт запускается, а зависимости можно дотянуть вручную.
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

if __name__ == "__main__":
    print(f"Updater module version: {__version__}")
    print(f"Script directory: {_get_script_dir()}")
    
    test_versions = [
        ("1.0.0", "1.0.1", True),
        ("1.0.0", "1.0.0", False),
        ("1.0.0", "0.9.9", False),
        ("1.4.0", "2.0.0", True),
        ("v1.0.0", "1.0.1", True),
    ]
    
    print("\nVersion comparison test:")
    for current, remote, expected in test_versions:
        result = _is_newer_version(current, remote)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {current} vs {remote}: {result} (expected {expected})")
