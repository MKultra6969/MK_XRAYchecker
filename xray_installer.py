# +═════════════════════════════════════════════════════════════════════════+
# ║                     XRAY INSTALLER MODULE                               ║
# ║          Автоустановка и обновление Xray core                           ║
# +═════════════════════════════════════════════════════════════════════════+
# ║                               by MKultra69                              ║
# +═════════════════════════════════════════════════════════════════════════+

import os
import sys
import re
import stat
import json
import shutil
import platform
import tempfile
import subprocess
import zipfile
import tarfile
import gzip
import requests

__version__ = "1.1.3"

XRAY_REPO = {
    "owner": "XTLS",
    "repo": "Xray-core"
}

MIHOMO_REPO = {
    "owner": "MetaCubeX",
    "repo": "mihomo"
}

INSTALL_DIR = "bin"

OS_MAP = {
    "windows": "windows",
    "linux": "linux",
    "darwin": "macos",
    "freebsd": "freebsd",
    "openbsd": "openbsd",
}

ARCH_MAP = {
    # x86_64
    "x86_64": "64",
    "amd64": "64",
    "x64": "64",
    
    # x86 (32-bit)
    "i386": "32",
    "i686": "32",
    "x86": "32",
    
    # ARM 64-bit
    "aarch64": "arm64-v8a",
    "arm64": "arm64-v8a",
    
    # ARM 32-bit
    "armv7l": "arm32-v7a",
    "armv7": "arm32-v7a",
    "armv6l": "arm32-v6",
    "armv6": "arm32-v6",
    "armv5l": "arm32-v5",
    "armv5tel": "arm32-v5",
    
    # MIPS
    "mips": "mips32",
    "mips64": "mips64",
    "mipsel": "mips32le",
    "mips64el": "mips64le",
    
    # RISC-V
    "riscv64": "riscv64",
    
    # S390X (IBM mainframe)
    "s390x": "s390x",
    
    # PowerPC
    "ppc64le": "ppc64le",
}

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

def resolve_platform():
    raw_os = platform.system().lower()
    raw_arch = platform.machine().lower()
    
    os_name = OS_MAP.get(raw_os)
    if not os_name:
        _safe_print(f"[yellow]Неизвестная OS: {raw_os}[/]")
        return None, None
    
    arch_name = ARCH_MAP.get(raw_arch)
    if not arch_name:
        _safe_print(f"[yellow]Неизвестная архитектура: {raw_arch}[/]")
        return None, None
    
    return os_name, arch_name

def resolve_xray_asset_name(os_name, arch_name):
    if not os_name or not arch_name:
        return None
    return f"Xray-{os_name}-{arch_name}.zip"

def get_latest_xray_release():

    api_url = f"https://api.github.com/repos/{XRAY_REPO['owner']}/{XRAY_REPO['repo']}/releases/latest"
    
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": f"v2rayChecker-XrayInstaller/{__version__}"
    }
    
    try:
        _safe_print("[dim]Проверка последней версии Xray...[/]")
        
        resp = requests.get(api_url, headers=headers, timeout=15)
        
        if resp.status_code == 200:
            data = resp.json()
            
            release_info = {
                "tag_name": data.get("tag_name", ""),
                "version": data.get("tag_name", "").lstrip('v'),
                "assets": data.get("assets", []),
                "published_at": data.get("published_at", ""),
                "html_url": data.get("html_url", ""),
            }
            
            _safe_print(f"[dim]Последняя версия Xray: {release_info['version']}[/]")
            return release_info
        else:
            _safe_print(f"[yellow]GitHub API вернул {resp.status_code}[/]")
            return None
            
    except requests.exceptions.Timeout:
        _safe_print("[yellow]Таймаут при обращении к GitHub API[/]")
    except requests.exceptions.RequestException as e:
        _safe_print(f"[yellow]Ошибка сети: {e}[/]")
    except Exception as e:
        _safe_print(f"[yellow]Ошибка при проверке релизов Xray: {e}[/]")
    
    return None

def get_specific_xray_release(version):

    tag = version if version.startswith('v') else f"v{version}"
    
    api_url = f"https://api.github.com/repos/{XRAY_REPO['owner']}/{XRAY_REPO['repo']}/releases/tags/{tag}"
    
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": f"v2rayChecker-XrayInstaller/{__version__}"
    }
    
    try:
        resp = requests.get(api_url, headers=headers, timeout=15)
        
        if resp.status_code == 200:
            data = resp.json()
            return {
                "tag_name": data.get("tag_name", ""),
                "version": data.get("tag_name", "").lstrip('v'),
                "assets": data.get("assets", []),
                "published_at": data.get("published_at", ""),
                "html_url": data.get("html_url", ""),
            }
        elif resp.status_code == 404:
            _safe_print(f"[yellow]Версия {tag} не найдена[/]")
        
    except Exception as e:
        _safe_print(f"[yellow]Ошибка при получении версии {tag}: {e}[/]")
    
    return None

def _get_github_release(repo_cfg, tag=None):
    if tag:
        api_url = f"https://api.github.com/repos/{repo_cfg['owner']}/{repo_cfg['repo']}/releases/tags/{tag}"
    else:
        api_url = f"https://api.github.com/repos/{repo_cfg['owner']}/{repo_cfg['repo']}/releases/latest"

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": f"v2rayChecker-XrayInstaller/{__version__}"
    }

    try:
        resp = requests.get(api_url, headers=headers, timeout=20)
        if resp.status_code != 200:
            if resp.status_code == 404 and tag:
                _safe_print(f"[yellow]Версия {tag} не найдена[/]")
            else:
                _safe_print(f"[yellow]GitHub API вернул {resp.status_code}[/]")
            return None

        data = resp.json()
        return {
            "tag_name": data.get("tag_name", ""),
            "version": data.get("tag_name", "").lstrip('v'),
            "assets": data.get("assets", []),
            "published_at": data.get("published_at", ""),
            "html_url": data.get("html_url", ""),
        }
    except requests.exceptions.Timeout:
        _safe_print("[yellow]Таймаут при обращении к GitHub API[/]")
    except requests.exceptions.RequestException as e:
        _safe_print(f"[yellow]Ошибка сети: {e}[/]")
    except Exception as e:
        _safe_print(f"[yellow]Ошибка получения релиза: {e}[/]")
    return None

def get_latest_mihomo_release():
    _safe_print("[dim]Проверка последней версии Mihomo...[/]")
    return _get_github_release(MIHOMO_REPO)

def get_specific_mihomo_release(version):
    tag = version if version.startswith('v') else f"v{version}"
    return _get_github_release(MIHOMO_REPO, tag=tag)

def get_current_xray_version(core_path):

    if not core_path or not os.path.exists(core_path):
        return None
    
    try:
        result = subprocess.run(
            [core_path, "version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        output = result.stdout + result.stderr

        match = re.search(r'(?:Xray|V2Ray|v2ray)\s+(\d+\.\d+\.\d+)', output, re.IGNORECASE)
        if match:
            return match.group(1)
        
        match = re.search(r'Version[:\s]+(\d+\.\d+\.\d+)', output, re.IGNORECASE)
        if match:
            return match.group(1)
            
    except subprocess.TimeoutExpired:
        _safe_print("[dim]Таймаут при получении версии Xray[/]")
    except Exception as e:
        _safe_print(f"[dim]Ошибка получения версии Xray: {e}[/]")
    
    return None

def _resolve_mihomo_asset(release_info):
    if not release_info:
        return None, None

    raw_os = platform.system().lower()
    raw_arch = platform.machine().lower()

    os_tokens_map = {
        "windows": ["windows", "win"],
        "linux": ["linux"],
        "darwin": ["darwin", "macos", "mac", "osx"],
        "freebsd": ["freebsd"],
        "openbsd": ["openbsd"],
    }
    arch_tokens_map = {
        "x86_64": ["amd64", "x86_64", "x64"],
        "amd64": ["amd64", "x86_64", "x64"],
        "x64": ["amd64", "x86_64", "x64"],
        "i386": ["386", "i386", "x86"],
        "i686": ["386", "i386", "x86"],
        "x86": ["386", "i386", "x86"],
        "aarch64": ["arm64", "aarch64"],
        "arm64": ["arm64", "aarch64"],
        "armv7l": ["armv7", "arm", "armv7l"],
        "armv7": ["armv7", "arm"],
        "riscv64": ["riscv64"],
        "s390x": ["s390x"],
        "ppc64le": ["ppc64le"],
    }

    os_tokens = os_tokens_map.get(raw_os, [raw_os])
    arch_tokens = arch_tokens_map.get(raw_arch, [raw_arch])

    candidates = []
    for asset in release_info.get("assets", []):
        name = asset.get("name", "")
        lname = name.lower()
        if "mihomo" not in lname:
            continue
        if not lname.endswith((".zip", ".gz", ".tgz", ".tar.gz")):
            continue
        if any(x in lname for x in ("sha256", "sha512", "sum", "sums", ".sig", "signature", "sbom", ".txt")):
            continue
        if not any(tok in lname for tok in os_tokens):
            continue
        if not any(tok in lname for tok in arch_tokens):
            continue

        score = 0
        if "compatible" in lname:
            score += 30
        if lname.endswith(".zip"):
            score += 10
        if "alpha" not in lname:
            score += 2
        candidates.append((score, len(name), asset))

    if not candidates:
        return None, None

    candidates.sort(key=lambda x: (-x[0], x[1]))
    best_asset = candidates[0][2]
    return best_asset.get("name"), best_asset.get("browser_download_url")

def _extract_mihomo_archive(tmp_path, asset_name, install_path, os_name):
    tmp_extract_dir = tempfile.mkdtemp(prefix="mihomo_extract_")
    try:
        lower_name = (asset_name or "").lower()
        if lower_name.endswith(".zip"):
            with zipfile.ZipFile(tmp_path, 'r') as zf:
                zf.extractall(tmp_extract_dir)
        elif lower_name.endswith(".tar.gz") or lower_name.endswith(".tgz"):
            with tarfile.open(tmp_path, 'r:gz') as tf:
                tf.extractall(tmp_extract_dir)
        elif lower_name.endswith(".gz"):
            out_name = os.path.splitext(os.path.basename(asset_name))[0] or "mihomo"
            out_path = os.path.join(tmp_extract_dir, out_name)
            with gzip.open(tmp_path, 'rb') as src, open(out_path, 'wb') as dst:
                shutil.copyfileobj(src, dst)
        else:
            _safe_print(f"[red]Неподдерживаемый архив Mihomo: {asset_name}[/]")
            return None

        core_candidates = []
        for root, _, files in os.walk(tmp_extract_dir):
            for fname in files:
                lname = fname.lower()
                if "mihomo" not in lname and "clash-meta" not in lname:
                    continue
                if os_name == "windows" and not lname.endswith(".exe"):
                    continue
                if os_name != "windows" and lname.endswith(".exe"):
                    continue
                full_path = os.path.join(root, fname)
                try:
                    size = os.path.getsize(full_path)
                except Exception:
                    size = 0
                core_candidates.append((size, full_path))

        if not core_candidates:
            _safe_print("[red]Бинарник mihomo не найден в архиве[/]")
            return None

        core_candidates.sort(key=lambda x: x[0], reverse=True)
        selected_binary = core_candidates[0][1]

        final_name = "mihomo.exe" if os_name == "windows" else "mihomo"
        final_path = os.path.join(install_path, final_name)
        if os.path.exists(final_path):
            os.remove(final_path)
        shutil.move(selected_binary, final_path)
        return final_path
    finally:
        try:
            shutil.rmtree(tmp_extract_dir, ignore_errors=True)
        except Exception:
            pass

def download_and_install_xray(release_info, cfg):

    if not release_info:
        return None
    
    os_name, arch_name = resolve_platform()
    if not os_name or not arch_name:
        _safe_print("[red]Не удалось определить платформу[/]")
        return None
    
    asset_name = resolve_xray_asset_name(os_name, arch_name)
    if not asset_name:
        return None
    
    _safe_print(f"[dim]Ищем ассет: {asset_name}[/]")
    
    download_url = None
    for asset in release_info.get("assets", []):
        if asset.get("name") == asset_name:
            download_url = asset.get("browser_download_url")
            break
    
    if not download_url:
        _safe_print(f"[red]Ассет {asset_name} не найден в релизе[/]")
        _safe_print(f"[dim]Доступные ассеты: {[a['name'] for a in release_info.get('assets', [])]}[/]")
        return None
    
    script_dir = _get_script_dir()
    install_path = os.path.join(script_dir, INSTALL_DIR)
    
    try:
        os.makedirs(install_path, exist_ok=True)
    except Exception as e:
        _safe_print(f"[red]Не удалось создать директорию {install_path}: {e}[/]")
        return None
    
    _safe_print(f"[cyan]Скачивание Xray {release_info['version']}...[/]")
    
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
            tmp_path = tmp_file.name
            
            resp = requests.get(download_url, stream=True, timeout=120)
            resp.raise_for_status()
            
            total_size = int(resp.headers.get('content-length', 0))
            downloaded = 0
            
            for chunk in resp.iter_content(chunk_size=65536):
                if chunk:
                    tmp_file.write(chunk)
                    downloaded += len(chunk)
                    
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        if downloaded % (1024 * 1024) < 65536:
                            _safe_print(f"[dim]Загружено: {downloaded // (1024*1024)}MB / {total_size // (1024*1024)}MB ({percent:.0f}%)[/]")
    
    except Exception as e:
        _safe_print(f"[red]Ошибка скачивания: {e}[/]")
        return None
    
    _safe_print("[dim]Распаковка архива...[/]")
    
    try:
        with zipfile.ZipFile(tmp_path, 'r') as zf:
            xray_names = ['xray.exe', 'xray'] if os_name == 'windows' else ['xray']
            
            extracted_binary = None
            for name in zf.namelist():
                basename = os.path.basename(name)
                if basename in xray_names:
                    zf.extract(name, install_path)
                    extracted_binary = os.path.join(install_path, name)
                    
                    final_name = 'xray.exe' if os_name == 'windows' else 'xray'
                    final_path = os.path.join(install_path, final_name)
                    
                    if extracted_binary != final_path:
                        if os.path.exists(final_path):
                            os.remove(final_path)
                        shutil.move(extracted_binary, final_path)
                        extracted_binary = final_path
                    
                    break
            
            if not extracted_binary or not os.path.exists(extracted_binary):
                _safe_print(f"[red]Бинарник xray не найден в архиве[/]")
                return None
            
            geo_files = ['geoip.dat', 'geosite.dat']
            for name in zf.namelist():
                basename = os.path.basename(name)
                if basename in geo_files:
                    dest_path = os.path.join(script_dir, basename)
                    if not os.path.exists(dest_path):
                        zf.extract(name, script_dir)
                        extracted = os.path.join(script_dir, name)
                        if extracted != dest_path and os.path.exists(extracted):
                            shutil.move(extracted, dest_path)
    
    except zipfile.BadZipFile:
        _safe_print("[red]Скачанный файл не является валидным ZIP архивом[/]")
        return None
    except Exception as e:
        _safe_print(f"[red]Ошибка распаковки: {e}[/]")
        return None
    finally:
        try:
            os.remove(tmp_path)
        except:
            pass
    
    if os_name != 'windows':
        try:
            os.chmod(extracted_binary, 
                     os.stat(extracted_binary).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            _safe_print(f"[dim]Установлены права на выполнение[/]")
        except Exception as e:
            _safe_print(f"[yellow]Не удалось установить права: {e}[/]")
    
    _safe_print(f"[bold green]✓ Xray {release_info['version']} установлен в {extracted_binary}[/]")
    
    return extracted_binary

def download_and_install_mihomo(release_info, cfg):
    if not release_info:
        return None

    os_name, _ = resolve_platform()
    if not os_name:
        _safe_print("[red]Не удалось определить платформу[/]")
        return None

    asset_name, download_url = _resolve_mihomo_asset(release_info)
    if not download_url:
        _safe_print("[red]Не найден подходящий ассет mihomo для текущей платформы[/]")
        names = [a.get("name", "") for a in release_info.get("assets", [])]
        _safe_print(f"[dim]Доступные ассеты: {names}[/]")
        return None

    script_dir = _get_script_dir()
    install_path = os.path.join(script_dir, INSTALL_DIR)
    os.makedirs(install_path, exist_ok=True)

    lower_asset = asset_name.lower()
    if lower_asset.endswith(".tar.gz"):
        suffix = ".tar.gz"
    elif lower_asset.endswith(".tgz"):
        suffix = ".tgz"
    elif lower_asset.endswith(".zip"):
        suffix = ".zip"
    elif lower_asset.endswith(".gz"):
        suffix = ".gz"
    else:
        suffix = ".tmp"

    _safe_print(f"[cyan]Скачивание Mihomo {release_info['version']} ({asset_name})...[/]")
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            tmp_path = tmp_file.name
            resp = requests.get(download_url, stream=True, timeout=180)
            resp.raise_for_status()
            for chunk in resp.iter_content(chunk_size=65536):
                if chunk:
                    tmp_file.write(chunk)

        extracted_binary = _extract_mihomo_archive(tmp_path, asset_name, install_path, os_name)
        if not extracted_binary:
            return None

        if os_name != "windows":
            os.chmod(
                extracted_binary,
                os.stat(extracted_binary).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

        _safe_print(f"[bold green]✓ Mihomo {release_info['version']} установлен в {extracted_binary}[/]")
        return extracted_binary
    except Exception as e:
        _safe_print(f"[red]Ошибка установки Mihomo: {e}[/]")
        return None
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except Exception:
                pass

def ensure_xray_installed(cfg):

    script_dir = _get_script_dir()
    
    os_name, _ = resolve_platform()
    binary_name = 'xray.exe' if os_name == 'windows' else 'xray'
    
    possible_paths = [
        os.path.join(script_dir, INSTALL_DIR, binary_name),
        os.path.join(script_dir, binary_name),
    ]
    
    existing_path = None
    for path in possible_paths:
        if os.path.exists(path):
            existing_path = path
            break
    
    if existing_path:
        current_version = get_current_xray_version(existing_path)
        if current_version:
            _safe_print(f"[dim]Найден Xray {current_version}: {existing_path}[/]")
        return existing_path
    
    autoinstall = cfg.get("autoinstall_xray", True)
    target_version = cfg.get("xray_version", "latest")
    
    if not autoinstall:
        try:
            from rich.prompt import Confirm
            should_install = Confirm.ask(
                "[bold yellow]Xray не найден. Установить автоматически?[/]",
                default=True
            )
        except ImportError:
            response = input("Xray не найден. Установить автоматически? [Y/n]: ").strip().lower()
            should_install = response in ('', 'y', 'yes', 'д', 'да')
        
        if not should_install:
            _safe_print("[dim]Установка отменена пользователем[/]")
            _safe_print("[dim]Скачайте Xray вручную: https://github.com/XTLS/Xray-core/releases[/]")
            return None
    else:
        _safe_print("[yellow]Xray не найден, начинаем автоустановку...[/]")
    
    if target_version == "latest":
        release_info = get_latest_xray_release()
    else:
        release_info = get_specific_xray_release(target_version)
        if not release_info:
            _safe_print(f"[yellow]Версия {target_version} не найдена, используем latest[/]")
            release_info = get_latest_xray_release()
    
    if not release_info:
        _safe_print("[red]Не удалось получить информацию о релизе Xray[/]")
        return None
    
    installed_path = download_and_install_xray(release_info, cfg)
    
    return installed_path

def ensure_mihomo_installed(cfg):
    script_dir = _get_script_dir()
    os_name, _ = resolve_platform()
    binary_name = "mihomo.exe" if os_name == "windows" else "mihomo"

    possible_paths = [
        os.path.join(script_dir, INSTALL_DIR, binary_name),
        os.path.join(script_dir, binary_name),
    ]

    for path in possible_paths:
        if os.path.exists(path):
            _safe_print(f"[dim]Найден Mihomo: {path}[/]")
            return path

    autoinstall = cfg.get("autoinstall_mihomo", True)
    target_version = cfg.get("mihomo_version", "latest")

    if not autoinstall:
        try:
            from rich.prompt import Confirm
            should_install = Confirm.ask(
                "[bold yellow]Mihomo не найден. Установить автоматически?[/]",
                default=True
            )
        except ImportError:
            response = input("Mihomo не найден. Установить автоматически? [Y/n]: ").strip().lower()
            should_install = response in ('', 'y', 'yes', 'д', 'да')

        if not should_install:
            _safe_print("[dim]Установка отменена пользователем[/]")
            _safe_print("[dim]Скачайте Mihomo вручную: https://github.com/MetaCubeX/mihomo/releases[/]")
            return None
    else:
        _safe_print("[yellow]Mihomo не найден, начинаем автоустановку...[/]")

    if target_version == "latest":
        release_info = get_latest_mihomo_release()
    else:
        release_info = get_specific_mihomo_release(target_version)
        if not release_info:
            _safe_print(f"[yellow]Версия {target_version} не найдена, используем latest[/]")
            release_info = get_latest_mihomo_release()

    if not release_info:
        _safe_print("[red]Не удалось получить информацию о релизе Mihomo[/]")
        return None

    return download_and_install_mihomo(release_info, cfg)

def ensure_core_installed(cfg, preferred_core="xray"):
    preferred = (preferred_core or "xray").strip().lower()
    if preferred == "mihomo":
        installed = ensure_mihomo_installed(cfg)
        if installed:
            return installed
        _safe_print("[yellow]Переходим на установку Xray как fallback[/]")
    return ensure_xray_installed(cfg)


def check_for_xray_update(core_path, cfg):

    current_version = get_current_xray_version(core_path)
    if not current_version:
        return False, None, None
    
    release_info = get_latest_xray_release()
    if not release_info:
        return False, current_version, None
    
    latest_version = release_info.get("version", "")
    
    try:
        current_parts = [int(x) for x in current_version.split('.')]
        latest_parts = [int(x) for x in latest_version.split('.')]
        
        while len(current_parts) < 3:
            current_parts.append(0)
        while len(latest_parts) < 3:
            latest_parts.append(0)
        
        needs_update = tuple(latest_parts) > tuple(current_parts)
        
    except ValueError:
        needs_update = False
    
    return needs_update, current_version, latest_version

if __name__ == "__main__":
    print(f"Xray Installer module version: {__version__}")
    print(f"Script directory: {_get_script_dir()}")
    
    os_name, arch_name = resolve_platform()
    print(f"\nCurrent platform:")
    print(f"  OS: {platform.system()} -> {os_name}")
    print(f"  Arch: {platform.machine()} -> {arch_name}")
    
    asset_name = resolve_xray_asset_name(os_name, arch_name)
    print(f"  Asset: {asset_name}")
    
    print("\nLatest Xray release:")
    release = get_latest_xray_release()
    if release:
        print(f"  Version: {release['version']}")
        print(f"  Published: {release['published_at']}")
        print(f"  Assets count: {len(release['assets'])}")
