
<div align="center">

# 🕷️ MK_XRAYchecker 🕷️

**Мощный, многопоточный чекер прокси V2Ray/Xray**  
*Быстро. Жестко. Эффективно.* - все как я люблю.

<p>
  <a href="https://github.com/MKultra6969/MK_XRAYchecker">
    <img src="https://img.shields.io/badge/VERSION-1.4.0-magenta?style=for-the-badge&logo=python" alt="Version">
  </a>
  <a href="http://www.wtfpl.net/">
    <img src="https://img.shields.io/badge/LICENSE-WTFPL-red?style=for-the-badge" alt="License">
  </a>
  <a href="https://t.me/MKplusULTRA">
    <img src="https://img.shields.io/badge/Telegram-MKplusULTRA-blue?style=for-the-badge&logo=telegram" alt="Telegram">
  </a>
</p>

![Главное меню](https://raw.githubusercontent.com/MKultra6969/MK_XRAYchecker/main/menuShowcase/1.3.0.png)
Главное меню


</div>
 
## ⚡ Описание

**MK_XRAYchecker** — Утилита на Python для массовой проверки доступности и задержки V2Ray/Xray прокси. Скрипт парсит конфиги из файлов или URL (Например GitHub Raw), декодирует Base64 (и другие форматы), создает временные конфиги и проверяет их через реальное ядро `Xray` или `Mihomo`.

Отдельно добавлен **MTProto checker** для Telegram proxy (`tg://proxy`, `t.me/proxy`) с собственной логикой проверки через Telegram API. Он **не использует** `Xray/Mihomo` и работает как отдельный режим.

### 🔥 Возможности
*   **Поддержка протоколов:** `VMess`, `VLESS`, `Trojan`, `Shadowsocks`, `Hysteria2`.
*   **Отдельный MTProto checker:** проверка Telegram proxy (`tg://proxy`, `t.me/proxy`) через реальный MTProto handshake и Telegram RPC probe.
*   **Парсинг:** Извлекает прокси из "каши" текста, Base64 строк, ссылок-подписок. 
*   **Подписки:** Поддерживает URL-подписки в формате ссылок и `Clash/Mihomo` YAML (`proxies:`), включая Base64-обёртку.
    - (Ну, то есть скрипту практически похуй в каком виде ты скормишь ему ссылки.)
*   **Batch Mode:** 1 ядро = 1 пачка прокси (для `xray` внутри пачки проверки идут параллельно). UP TO 1337 BATCHES.
*   **Режимы работы:** Красивое меню или CLI аргументы.
*   **Двухуровневое меню:** Отдельные разделы `Проверка / Настройки / Сервис` и компактный status-блок с текущими параметрами.
*   **Сортировка:** Автоматически сортирует рабочие прокси по пингу или скорости.
*   **Отсев по ping:** Можно задать порог `max_ping_ms` (например `500`) и автоматически выкидывать медленные прокси.
*   **SpeedTest:** Проверка скорости скачивания (опционально).
*   **Rich UI**: Ну всякие загрузочки менюшечки красивые.
*   **Конфиг**: Гибкий конфиг, с множеством параметров.
*   **Debug artifacts:** При падении ядра сохраняет `batch*.json` и лог в `./failed_batches` + печатает команду воспроизведения.
*   **Self-test URL:** Быстрый тест парсинга (чинит кейсы `&amp;`, `&amp%3B`, `%26amp%3B`).
*   **Безопаснее SS:** фильтрует Shadowsocks-ссылки с неподдерживаемыми шифрами (AEAD-only whitelist), чтобы не ловить `Exit: 23`.
*   **Более строгий REALITY:** валидирует `pbk` (base64url → строго 32 байта) и нормализует `sid` (shortId hex).
*   **Self-Update:** умеет обновлять `v2rayChecker.py`, `updater.py`, `aggregator.py` и MTProto-модули из GitHub репозитория (staged `.new` + `update.pending` + перезапуск).
*   **Auto-install core:** умеет автоматически ставить `xray` или `mihomo` (по `preferred_core`) в `./bin`.
*   **Свитч ядра:** переключение `auto/xray/mihomo` через CLI (`--engine`) или через интерактивное меню.
*   **MTProto в отдельном режиме:** свой output-файл, свой timeout/threads/max ping, свой пункт в меню.

---

## 🔄 Self-Update (автообновление)

Скрипт может проверять обновления на старте и подтягивать свежие python-файлы из GitHub Releases (fallback на raw `VERSION`).

### Как это работает
- При наличии апдейта скачиваются обновлённые файлы и сохраняются как `*.new`, создаётся `update.pending`, затем скрипт перезапускается.
- На следующем запуске `apply_pending_update_if_any()` применяет staged обновления (замена файлов + `.bak`).
- Updater отслеживает `v2rayChecker.py`, `updater.py`, `xray_installer.py`, `requirements.txt`, а также `aggregator.py` и MTProto-модули, если они есть в репозитории.
- После staged-обновления выполняется smoke-check: компиляция, импорт модулей и проверка доступности `Telethon` для MTProto режима.

### Как отключить
- CLI: `--no-update` (полностью пропустить проверку).
- Конфиг: `autoupdate`:
  - `true` — обновляется автоматически без вопросов.
  - `false` — если версия устарела, спросит подтверждение.

---

## ⚠️ ВАЖНО: Ядро (`Xray` / `Mihomo`)

Для работы скрипта **нужно** одно из ядер:
- `xray` / `xray.exe`
- `mihomo` / `mihomo.exe`

По умолчанию включена автоустановка: если ядра нет — скрипт попытается скачать архив из релизов и распаковать в `./bin`.

### 🛠️ Ручная установка (если нужно)
1. Выбери релизы нужного ядра:  
   👉 [**Xray-core releases**](https://github.com/XTLS/Xray-core/releases)  
   👉 [**Mihomo releases**](https://github.com/MetaCubeX/mihomo/releases)
2. Скачай архив под свою ОС/архитектуру.
3. Распакуй и положи бинарник рядом со скриптом или в `./bin` (`xray.exe` / `mihomo.exe`).

> 📂 Рекомендуемая структура:
> - `v2rayChecker.py`
> - `updater.py` (для self-update)
> - `xray_installer.py` (для автоустановки ядра)
> - `bin/xray.exe` или `bin/xray`
> - `bin/mihomo.exe` или `bin/mihomo`
> - `aggregator.py` (опционально, для `--agg`)

---

## 🚀 Установка и Запуск

### 1. Клонирование репозитория
```bash
git clone https://github.com/MKultra6969/MK_XRAYchecker
cd MK_XRAYchecker
```

### 2. Установка зависимостей
```bash
pip install -r requirements.txt
```

### 3. Запуск
**Интерактивный режим (Меню):**
```bash
python v2rayChecker.py
```

**CLI (примеры):**
```bash
# Проверка из файла
python v2rayChecker.py -f "proxies.txt"

# Проверка по ссылке-подписке
python v2rayChecker.py -u "https://example.com/sub"

# Указать количество потоков и таймаут
python v2rayChecker.py -f "list.txt" -T 50 -t 2

# MTProto checker по файлу
python v2rayChecker.py --mtproto -f "mtproto.txt"

# MTProto checker по прямой ссылке
python v2rayChecker.py --mtproto -u "tg://proxy?server=1.2.3.4&port=443&secret=0123456789abcdef0123456789abcdef"

# Проверка именно живых MTProto proxy без ping-фильтра
python v2rayChecker.py --mtproto -f "mtproto.txt" --max-ping 0

# Запустить без проверки обновлений
python v2rayChecker.py --no-update
```

---

## ⚙️ config.json (важные ключи)

Ключи добавляются автоматически при первом запуске (или при появлении новых полей).

- `autoupdate`: `true/false` — автообновление скрипта.
- `repo_owner`, `repo_name`, `repo_branch` — откуда подтягивать апдейты (GitHub).
- `autoinstall_xray`: `true|false` — автоустановка ядра при отсутствии.
- `xray_version`: `"latest"` или конкретный тег (например `"v1.8.10"`).
- `autoinstall_mihomo`: `true|false` — автоустановка `mihomo` при отсутствии.
- `mihomo_version`: `"latest"` или конкретный тег.
- `preferred_core`: `"auto"` / `"xray"` / `"mihomo"` — режим выбора ядра.
- `router_mode`: `true/false` — безопасный режим для роутеров/OpenWRT.
- `core_cleanup_mode`: `"owned"` / `"all"` / `"none"` — политика очистки старых процессов ядра.
- `max_ping_ms`: порог ping в миллисекундах для отсева (`0` = отключено).
- `core_path`: путь к ядру (например `xray`, `bin/xray`, `bin/mihomo`).
- `agg_countries`: список ISO2-кодов стран для предфильтра агрегатора (например `["RU","DE","GB"]`).
- `mtproto`: отдельный блок настроек Telegram proxy checker:
  - `enabled`: включен ли MTProto режим.
  - `api_id`, `api_hash`: Telegram API credentials для Telethon.
  - `threads`: число параллельных MTProto проверок.
  - `timeout`: таймаут MTProto probe в секундах.
  - `max_ping_ms`: отдельный ping-порог для MTProto.
  - `dc_probe_limit`: сколько лучших Telegram DC пробовать для одного MTProto proxy.
  - `crypto_backend`: режим crypto backend для MTProto: `auto` / `safe` / `unsafe`.
  - `output_file`: отдельный output-файл, например `sortedMtproto.txt`.

> ⚠️ `api_id` и `api_hash` лежат в `config.json` в открытом виде.

---


## 🧪 Self-test (v1.0.3)
Проверка, что URL-парсер корректно обрабатывает HTML/URL-экранирование в параметрах (`security/pbk/sid/flow/...`), плюс self-test MTProto parser.

```bash
python v2rayChecker.py --self-test
```

---

## 🐛 Debug Mode (v1.0.3)
Режим для отладки: 1 прокси на batch и 1 поток, чтобы быстро находить “плохие” ссылки/конфиги.

```bash
python v2rayChecker.py -f "proxies.txt" --debug
```

---

## 🧯 Отладка падений ядра
Если ядро не запустилось, скрипт сохранит файлы в `./failed_batches` и покажет команду воспроизведения для текущего ядра.

---

## 📱 MTProto Mode

MTProto checker работает отдельно от Xray/Mihomo:
- принимает только `tg://proxy?...` и `t.me/proxy?...`;
- использует `Telethon` и Telegram API credentials из `config.json`;
- поддерживает обычные MTProxy secrets, `dd`-варианты и `ee/FakeTLS`;
- автоматически ранжирует несколько Telegram DC по месту запуска checker и пробует лучшие из них;
- для `standard/dd` перебирает несколько MTProto transport-режимов, а для `ee` использует отдельный FakeTLS backend;
- сортирует результаты только по ping;
- не делает speed-test;
- показывает отдельные статусы `LIVE / CONN / DROP / UNREACH / FAIL`;
- пишет результат в отдельный файл (`sortedMtproto.txt` по умолчанию).

Грубая интерпретация статусов:
- `LIVE`: proxy прошёл MTProto connect и Telegram RPC probe.
- `CONN`: proxy принял MTProto connect, но не довёл до успешного Telegram RPC.
- `DROP`: proxy живой, но отфильтрован по `max_ping_ms`.
- `UNREACH`: до proxy не удалось поднять даже сырой TCP connect с текущей машины.
- `FAIL`: proxy не прошёл connect / handshake / probe.

Для проверки именно живых MTProto proxy, а не только быстрых, ставь `MTProto ping = 0` или `--max-ping 0`. Если укажешь `--speed` или `--sort speed` вместе с `--mtproto`, режим будет принудительно возвращён к ping-сортировке с предупреждением.

Пример блока в `config.json`:

```json
"mtproto": {
  "enabled": true,
  "api_id": 123456,
  "api_hash": "your_api_hash",
  "threads": 20,
  "timeout": 5,
  "max_ping_ms": 1500,
  "dc_probe_limit": 3,
  "crypto_backend": "auto",
  "output_file": "sortedMtproto.txt"
}
```

---

## ⚙️ Аргументы cli

| Аргумент | Описание |
| :--- | :--- |
| `-m`, `--menu` | Принудительный запуск интерактивного меню |
| `-f`, `--file` | Путь к `.txt`/`.json` с прокси или со списком URL-подписок |
| `-u`, `--url` | URL ссылка на подписку или список (v1.1.3)|
| `--agg` | Запустить встроенный агрегатор (граббер) прокси |
| `--mtproto` | Запустить отдельный checker MTProto proxy (`tg://proxy`, `t.me/proxy`) |
| `--mtproto-crypto` | Принудительный выбор MTProto crypto backend: `auto` / `safe` / `unsafe` |
| `--agg-cats` | Категории источников для агрегатора (например: `1 2`) |
| `--agg-filter` | Фильтр агрегатора по ключевым словам (например: `vless reality`) |
| `--agg-country` | Фильтр агрегатора по странам ISO2 (например: `RU DE GB`) (v1.1.4)|
| `-o`, `--output` | Файл для сохранения результатов. Для MTProto по дефолту: `sortedMtproto.txt` |
| `-T`, `--threads` | Лимит одновременно запущенных ядер или MTProto-воркеров |
| `-t`, `--timeout` | Таймаут ожидания ответа в секундах |
| `-l`, `--lport` | Стартовый локальный порт для ядер (по дефолту: 1080) |
| `-c`, `--core` | Путь к исполняемому файлу ядра (`xray`/`v2ray`/`mihomo`) |
| `--engine` | Режим выбора ядра: `auto` / `xray` / `mihomo` |
| `--router-mode` | Безопасный режим роутера (не убивать чужие процессы ядер) (v1.1.4)|
| `--cleanup-mode` | Очистка старых процессов: `owned` / `all` / `none` (v1.1.4)|
| `-d`, `--domain` | Тестовый домен для проверки подключения (по дефолту: Google/CF generate_204) |
| `--max-ping` | Отсев по ping (мс), `0` = отключить (для MTProto использует его отдельный блок) |
| `-n`, `--number` | Ограничить количество проверяемых прокси (взять первые N) |
| `--reuse` | Перепроверить файл результатов (`sortedProxy.txt`) |
| `-s`, `--shuffle` | Перемешать список перед проверкой |
| `--t2exec` | Время ожидания запуска ядра в секундах |
| `--t2kill` | Задержка после убийства процесса ядра |
| `--speed` | Включить тест скорости скачивания (вместо только пинга) |
| `--sort` | Метод сортировки результатов: `ping` или `speed` |
| `--speed-url` | Ссылка на файл для теста скорости |
| `--self-test` | Запустить самопроверку URL парсинга (v1.0.3) |
| `--debug` | Debug режим (1 proxy/batch, 1 thread) (v1.0.3) |
| `--no-update` | Пропустить проверку самообновления на старте (v1.1.0)|

---

## 🔮 В будущем

В планах допилить следующий функционал:
1. ВОЗМОЖНО телеграм бот.

## 💀 Credits & License

**Ваш покорный:** [MKultra69](https://github.com/MKultra6969)  
**Веб:** [mk69.su](http://mk69.su)

**FELIX:** [Оригинал aggregator.py + хороший фидбек](https://github.com/y9felix/s)

### 📜 License
Проект КАК ВСЕГДА распространяется под лицензией **WTFPL** (Do What The Fuck You Want To Public License).
