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
    ("xray_installer.py", True)   # обязательный
]

PENDING_MARKER = "update.pending"

def _get_script_dir():
    return os.path.dirname(os.path.abspath(__file__))

def _safe_print(msg, style=None):
    try:
        from rich.console import Console
        console = Console()
        console.print(msg, style=style)
    except ImportError:
        import re
        clean_msg = re.sub(r'\[.*?\]', '', str(msg))
        print(clean_msg)

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
        
        print(f"[UPDATER] Применение обновления до версии {version}...")
        
        applied = []
        for filename in files:
            new_path = os.path.join(script_dir, f"{filename}.new")
            target_path = os.path.join(script_dir, filename)
            backup_path = os.path.join(script_dir, f"{filename}.bak")
            
            if not os.path.exists(new_path):
                print(f"[UPDATER] Предупреждение: {filename}.new не найден, пропуск")
                continue
            
            try:
                if os.path.exists(target_path):
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                    os.rename(target_path, backup_path)
                
                os.rename(new_path, target_path)
                applied.append(filename)
                print(f"[UPDATER] ✓ Обновлён: {filename}")
                
            except Exception as e:
                print(f"[UPDATER] ✗ Ошибка при обновлении {filename}: {e}")
                
                if os.path.exists(backup_path) and not os.path.exists(target_path):
                    try:
                        os.rename(backup_path, target_path)
                        print(f"[UPDATER] Восстановлен {filename} из backup")
                    except:
                        pass
        
        os.remove(marker_path)
        
        for filename in files:
            new_path = os.path.join(script_dir, f"{filename}.new")
            if os.path.exists(new_path):
                try:
                    os.remove(new_path)
                except:
                    pass
        
        if applied:
            print(f"[UPDATER] Обновление завершено ({len(applied)} файлов)")
            return True
        
        return False
        
    except Exception as e:
        print(f"[UPDATER] Ошибка при применении обновления: {e}")
        
        try:
            os.remove(marker_path)
        except:
            pass
        
        return False

def maybe_self_update(cfg):
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
