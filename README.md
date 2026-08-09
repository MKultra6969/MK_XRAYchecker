
<div align="center">

# 🕷️ MK_XRAYchecker 🕷️

**Мощный, многопоточный чекер прокси V2Ray/Xray**  
*Быстро. Жестко. Эффективно.* - все как я люблю.

<p>
  <a href="https://github.com/MKultra6969/MK_XRAYchecker/releases">
    <img src="https://img.shields.io/github/v/release/MKultra6969/MK_XRAYchecker?style=for-the-badge&logo=python&color=magenta&label=VERSION" alt="Version">
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

---

## 📖 Содержание

- [Быстрый старт](#-быстрый-старт)
- [Возможности](#-возможности)
- [Типовые сценарии](#-типовые-сценарии)
- [TCP ping отсев](#-tcp-ping-отсев)
- [Ядро: Xray / Mihomo](#-ядро-xray--mihomo)
- [MTProto режим](#-mtproto-режим)
- [Настройка](#-настройка)
- [Обновления](#-обновления)
- [Диагностика](#-диагностика)
- [Документация](#-документация)
- [Credits & License](#-credits--license)

---

## 🚀 Быстрый старт

```bash
git clone https://github.com/MKultra6969/MK_XRAYchecker
cd MK_XRAYchecker
pip install -r requirements.txt
python v2rayChecker.py
```

Последняя команда откроет интерактивное меню. Ядро (`xray` / `mihomo`) скрипт скачает сам при первом запуске — подробности в разделе [Ядро](#-ядро-xray--mihomo).

---

## 🔥 Возможности

### Проверка прокси
*   **Поддержка протоколов:** `VLESS`, `VMess`, `Trojan`, `Shadowsocks`, `Hysteria2`, `AnyTLS`, `TUIC`, а также native Mihomo YAML-типы.
*   **Batch Mode:** 1 ядро = 1 пачка прокси (для `xray` внутри пачки проверки идут параллельно). UP TO 1337 BATCHES.
*   **Два ядра:** `Xray` и `Mihomo`, выбор `auto/xray/mihomo` через CLI (`--engine`) или интерактивное меню.
*   **Сортировка:** Автоматически сортирует рабочие прокси по пингу или скорости.
*   **TCP ping отсев:** Перед запуском ядра checker делает обычный TCP-коннект до `host:port` и выкидывает мёртвые ссылки. Ядро не тратит время на то, что и так не отвечает. Настраивается целиком: таймаут, потоки, ретраи, порог RTT.
*   **Отсев по ping:** Можно задать порог `max_ping_ms` (например `500`) и автоматически выкидывать медленные прокси.
*   **SpeedTest:** Проверка скорости скачивания (опционально).

### Ввод и парсинг
*   **Парсинг:** Извлекает прокси из "каши" текста, Base64 строк, ссылок-подписок.
*   **Подписки:** Поддерживает URL-подписки в формате ссылок и `Clash/Mihomo` YAML (`proxies:`), включая Base64-обёртку.
    - (Ну, то есть скрипту практически похуй в каком виде ты скормишь ему ссылки.)
*   **Строгая валидация:** отсеивает SS с неподдерживаемыми шифрами и невалидный REALITY ещё до запуска ядра — [подробнее](docs/protocols.md).

### MTProto (Telegram)
*   **Отдельный checker:** проверка Telegram proxy (`tg://proxy`, `t.me/proxy`) через реальный MTProto handshake и Telegram RPC probe.
*   **Свой режим целиком:** отдельный output-файл, свой timeout/threads/max ping, свой пункт в меню.
*   **MTProto Promo:** умеет читать `help.getPromoData` через авторизованную Telethon session и показывать promo-канал в логе, таблице и sidecar JSON.
*   **MTProto Login:** отдельный CLI/TUI вход для promo data с поддержкой Telegram-кода и 2FA-пароля.

### Автоматизация и UI
*   **Режимы работы:** Красивое меню или CLI аргументы.
*   **Двухуровневое меню:** Отдельные разделы `Проверка / Настройки / Сервис` и компактный status-блок с текущими параметрами.
*   **Rich UI**: Ну всякие загрузочки менюшечки красивые.
*   **Конфиг**: Гибкий конфиг, с множеством параметров.
*   **Self-Update:** обновляет сам себя из GitHub репозитория.
*   **Auto-install + автообновление ядер:** ставит и держит в актуальных версиях `Telethon`, `Xray-core` и `Mihomo`.

---

## 🚀 Типовые сценарии

```bash
# Интерактивное меню
python v2rayChecker.py

# Проверка из файла
python v2rayChecker.py -f "proxies.txt"

# Проверка по ссылке-подписке
python v2rayChecker.py -u "https://example.com/sub"

# Указать количество потоков и таймаут
python v2rayChecker.py -f "list.txt" -T 50 -t 2

# MTProto checker по файлу
python v2rayChecker.py --mtproto -f "mtproto.txt"

# Только TCP ping отсев: живые host:port в файл, ядро не запускается
python v2rayChecker.py --tcp-ping-only -f "huge_list.txt" -o "tcp_alive.txt"

# Запустить без проверки обновлений
python v2rayChecker.py --no-update
```

Полная таблица аргументов — в [docs/cli.md](docs/cli.md).

---

## 📡 TCP ping отсев

Перед тем как поднимать ядро, checker проверяет самое дешёвое: принимает ли `host:port` обычный TCP-коннект. Мёртвые ссылки отваливаются здесь, и ядро запускается только для тех, что вообще отвечают.

```bash
# отсев включён по умолчанию, отключить на один запуск
python v2rayChecker.py -f "list.txt" --no-tcp-ping

# подкрутить под свой канал
python v2rayChecker.py -f "list.txt" --tcp-ping-timeout 2 --tcp-ping-concurrency 1000

# выкинуть ещё и всё, до чего TCP RTT больше 300 мс
python v2rayChecker.py -f "list.txt" --tcp-ping-max-ms 300
```

Что нужно знать:

- **UDP/QUIC-протоколы** (`hysteria`, `hysteria2`, `tuic`, `wireguard`) отсев **не трогает**: TCP-коннект на их порт ничего не проверяет и выбросил бы живые прокси. Отключается ключом `skip_udp`.
- Ссылки без распознанного `host:port` проходят дальше нетронутыми — отсев удаляет только то, что реально проверил.
- Ретраится только timeout. `refused` — окончательный ответ хоста, повторять его бессмысленно.
- `--tcp-ping-max-ms` — это порог **TCP RTT до сервера**, а не ping через прокси. Второй, полноценный порог — это `--max-ping`.

**Меню:** `Настройки → TCP ping отсев` (все параметры) и `Проверка → TCP ping отсев` (прогнать файл только через отсев).

Все ключи блока `tcp_ping` — в [docs/config.md](docs/config.md).

---

## 🔩 Ядро: Xray / Mihomo

Для работы скрипта **нужно** одно из ядер:
- `xray` / `xray.exe`
- `mihomo` / `mihomo.exe`

По умолчанию включена автоустановка: если ядра нет — скрипт попытается скачать архив из релизов и распаковать в `./bin`. Ручная установка нужна редко.

<details>
<summary>🛠️ Ручная установка (если нужно)</summary>

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

</details>

Какое ядро под какую ссылку выбирается и почему — в [docs/protocols.md](docs/protocols.md).

---

## 📱 MTProto режим

MTProto checker работает отдельно от Xray/Mihomo: принимает только `tg://proxy?...` и `t.me/proxy?...`, использует `Telethon` и Telegram API credentials из `config.json`, сортирует только по ping и не делает speed-test.

```bash
# Проверить список Telegram proxy
python v2rayChecker.py --mtproto -f "mtproto.txt"

# Один раз авторизовать session для MTProto Promo
python v2rayChecker.py --mtproto-login
```

Результаты приходят со статусами `LIVE / CONN / DROP / UNREACH / SOFT / FAIL` — это не просто «живой/мёртвый», расшифровка каждого статуса, настройка `probe_policy`, promo-данные и ToS — в **[docs/mtproto.md](docs/mtproto.md)**.

> Для проверки именно живых MTProto proxy, а не только быстрых, ставь `MTProto ping = 0` или `--max-ping 0`.

---

## 🔧 Настройка

Все настройки лежат в `config.json`, ключи добавляются автоматически при первом запуске. Самое ходовое:

| Ключ | Описание |
| :--- | :--- |
| `preferred_core` | `"auto"` / `"xray"` / `"mihomo"` — режим выбора ядра |
| `core_path` | путь к ядру (например `xray`, `bin/xray`, `bin/mihomo`) |
| `threads` | сколько ядер запускается одновременно |
| `timeout` | таймаут ответа в секундах |
| `max_ping_ms` | порог ping в миллисекундах для отсева (`0` = отключено) |
| `tcp_ping` | блок TCP ping отсева перед запуском ядра (`enabled`, `timeout`, `concurrency`, ...) |
| `router_mode` | `true/false` — безопасный режим для роутеров/OpenWRT |
| `core_cleanup_mode` | `"owned"` / `"all"` / `"none"` — политика очистки старых процессов ядра |
| `autoupdate` | `true/false` — автообновление скрипта |
| `mtproto` | отдельный блок настроек Telegram proxy checker |

**Полный справочник всех ключей** (проверка, ядро, speedtest, обновления, агрегатор, MTProto) — в **[docs/config.md](docs/config.md)**.

---

## 🔄 Обновления

Обновляются отдельно две вещи, и обе — автоматически:

- **Сам скрипт** — проверяет обновления на старте и подтягивает свежие python-файлы из GitHub Releases (staged `.new` + перезапуск + smoke-check).
- **Ядра** — `Telethon`, `Xray-core` и `Mihomo` держатся в актуальных версиях, с бэкапом и откатом при провале. Обновляется только уже установленное ядро.

```bash
# проверить и обновить ядра прямо сейчас, затем выйти
python v2rayChecker.py --update-cores

# запуск вообще без обновлений (и скрипта, и ядер)
python v2rayChecker.py --no-update
```

**Меню:** `Настройки → Ядра: автообновление` — мастер-выключатель, тумблеры на каждое ядро, режим `auto`/`ask`, интервал, ручная проверка и таблица версий.

Как это работает изнутри, что откатывается при провале, почему Telethon залочен на ветке `1.x` и как всё это отключить — в **[docs/updates.md](docs/updates.md)**.

---

## 🧯 Диагностика

**Self-test (v1.0.3)** — проверка, что URL-парсер корректно обрабатывает HTML/URL-экранирование в параметрах (`security/pbk/sid/flow/...`), плюс self-test MTProto parser. Чинит кейсы `&amp;`, `&amp%3B`, `%26amp%3B`.

```bash
python v2rayChecker.py --self-test
```

**Debug Mode (v1.0.3)** — 1 прокси на batch и 1 поток, чтобы быстро находить “плохие” ссылки/конфиги.

```bash
python v2rayChecker.py -f "proxies.txt" --debug
```

**Падения ядра** — если ядро не запустилось, скрипт сохранит `batch*.json` и лог в `./failed_batches` и покажет команду воспроизведения для текущего ядра.

---

## 📚 Документация

| Документ | О чём |
| :--- | :--- |
| [docs/cli.md](docs/cli.md) | Все аргументы командной строки |
| [docs/config.md](docs/config.md) | Все ключи `config.json` с дефолтами |
| [docs/mtproto.md](docs/mtproto.md) | MTProto режим: статусы, promo, probe_policy |
| [docs/updates.md](docs/updates.md) | Self-update скрипта и автообновление ядер |
| [docs/protocols.md](docs/protocols.md) | Политика поддержки протоколов и выбора ядра (Issue #14) |
| [changelog.md](changelog.md) | История изменений |

---

## 🔮 В будущем

В планах допилить следующий функционал:
1. ВОЗМОЖНО телеграм бот.

## 💀 Credits & License

**Ваш покорный:** [MKultra69](https://github.com/MKultra6969)  
**Веб:** [mk69.su](http://mk69.su)

**FELIX:** [Оригинал aggregator.py + хороший фидбек](https://github.com/y9felix/s)

**@loliconshik:** [Telegram](https://t.me/loliconshik) — за идею TCP ping отсева

### 📜 License
Проект КАК ВСЕГДА распространяется под лицензией **WTFPL** (Do What The Fuck You Want To Public License).
