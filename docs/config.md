# ⚙️ config.json — полный справочник

Ключи добавляются автоматически при первом запуске (или при появлении новых полей). В таблицах — значение по умолчанию из `DEFAULT_CONFIG`.

Самое нужное для старта — в [README](../README.md#-настройка).

---

## Проверка прокси

| Ключ | По умолчанию | Описание |
| :--- | :--- | :--- |
| `threads` | `20` | Сколько ядер запускается одновременно |
| `proxies_per_batch` | `50` | Сколько прокси обрабатывает ОДНО ядро |
| `max_internal_threads` | `50` | Сколько параллельных проверок идёт внутри одного ядра |
| `timeout` | `3` | Таймаут ответа в секундах (повышать в случае огромного пинга) |
| `test_domain` | `https://www.google.com/generate_204` | Ссылка, по которой чекаются прокси. Можно поменять в случае блокировок в разных странах (`http://cp.cloudflare.com/generate_204`) |
| `max_ping_ms` | `666` | Порог ping в миллисекундах для отсева (`0` = отключено) |
| `output_file` | `sortedProxy.txt` | Имя файла с отфильтрованными прокси |
| `sort_by` | `ping` | Сортировка результатов: `ping` или `speed` |
| `shuffle` | `false` | Перемешивать список перед проверкой |
| `debug_mode` | `false` | При `true` используется `proxies_per_batch=1` и `threads=1` — для быстрого поиска проблемной ссылки |

## TCP ping отсев

Блок `tcp_ping` — быстрый TCP-коннект до `host:port` **до** запуска ядра. Мёртвые ссылки выкидываются здесь, и ядро на них не тратится. Идея: Telegram [@loliconshik](https://t.me/loliconshik).

По умолчанию отсев **выключен**: он судит прокси по TCP-коннекту с твоей машины, и на кривом канале может выкинуть живые ссылки. Включай осознанно — `"enabled": true`, пункт меню или флаг `--tcp-ping`.

| Ключ | По умолчанию | Описание |
| :--- | :--- | :--- |
| `enabled` | `false` | Мастер-выключатель отсева |
| `timeout` | `3.0` | Таймаут одной TCP-попытки (сек). Ниже `2.5` не стоит: на Windows `ConnectEx` отдаёт `refused` только через ~2 сек, и отказ начнёт читаться как timeout |
| `concurrency` | `500` | Сколько TCP-коннектов держится одновременно |
| `retries` | `1` | Доп. попытки перед вердиктом «мёртв». Ретраится только `timeout`: `refused`/`unreachable` — окончательный ответ хоста |
| `max_latency_ms` | `0` | Верхний порог TCP RTT в мс. `0` = только живой/мёртвый, без порога |
| `skip_udp` | `true` | Не трогать UDP/QUIC-протоколы (`hysteria`, `hysteria2`, `tuic`, `wireguard`, `shadowquic`, `masque`) — TCP-коннект на их порт ничего не доказывает и выбросил бы живые прокси |
| `resolve_timeout` | `5.0` | Таймаут DNS-резолва хоста (сек). Резолв кешируется на весь прогон |
| `max_ips_per_host` | `2` | Сколько A/AAAA записей пробовать, если хост резолвится в несколько IP |
| `report_file` | `""` | Файл со списком живых `ip:port` и их RTT. Пусто = не писать |

```json
"tcp_ping": {
    "enabled": false,
    "timeout": 3.0,
    "concurrency": 500,
    "retries": 1,
    "max_latency_ms": 0,
    "skip_udp": true,
    "resolve_timeout": 5.0,
    "max_ips_per_host": 2,
    "report_file": ""
}
```

> Ссылки без распознанного `host:port` отсев не трогает — он удаляет только то, что реально проверил.
> `max_latency_ms` — это RTT до сервера, а не ping через прокси. Полноценный порог — `max_ping_ms`.

Флаги CLI для разового переопределения — в [docs/cli.md](cli.md#tcp-ping-отсев).

## Ядро

| Ключ | По умолчанию | Описание |
| :--- | :--- | :--- |
| `core_path` | `xray` | Путь к ядру (например `xray`, `bin/xray`, `bin/mihomo`) |
| `preferred_core` | `auto` | Режим выбора ядра: `auto` / `xray` / `mihomo` |
| `local_port_start` | `10000` | С какого порта запускаются ядра: 1080 → 1081 → 1082 = три потока (три ядра) |
| `core_startup_timeout` | `2.5` | Максимальное время ожидания старта ядра (ну если тупит) |
| `core_kill_delay` | `0.05` | Задержка после убийства процесса |
| `core_cleanup_mode` | `owned` | Политика очистки старых процессов ядра: `owned` / `all` / `none` |
| `router_mode` | `false` | Безопасный режим для роутеров/OpenWRT — не трогать чужие процессы |

## SpeedTest

| Ключ | По умолчанию | Описание |
| :--- | :--- | :--- |
| `check_speed` | `false` | Включить тест скорости скачивания |
| `speed_check_threads` | `3` | Потоки для speed-теста |
| `speed_test_url` | Cloudflare `__down` | Ссылка для скачивания |
| `speed_download_timeout` | `10` | Макс. время (сек) на скачивание файла. Чем больше — тем точнее замеры |
| `speed_connect_timeout` | `5` | Макс. время (сек) на подключение перед скачиванием. Пинг 4000 мс, скрипт ждёт 5000 мс — значит скорость будет замеряна |
| `speed_max_mb` | `10` | Лимит скачивания в МБ (чтобы не тратить трафик) |
| `speed_min_kb` | `1` | Минимальный порог данных в КБ. Если прокси скачал меньше — скорость будет `0.0` |
| `speed_targets` | список зеркал | Пул серверов для замера (Cloudflare, OVH, Tele2, Hetzner, Leaseweb, USA, Yandex) |

## Обновление скрипта

| Ключ | По умолчанию | Описание |
| :--- | :--- | :--- |
| `autoupdate` | `false` | `true` — обновляется автоматически без вопросов. `false` — если версия устарела, спросит подтверждение |
| `repo_owner` | `MKultra6969` | Откуда подтягивать апдейты. Можно поменять на свой форк |
| `repo_name` | `MK_XRAYchecker` | — |
| `repo_branch` | `main` | — |

## Установка и автообновление ядер

| Ключ | По умолчанию | Описание |
| :--- | :--- | :--- |
| `autoinstall_xray` | `true` | Автоматически скачать и установить Xray, если не найден |
| `xray_version` | `latest` | `"latest"` или конкретный тег (например `"v1.8.10"`) |
| `autoinstall_mihomo` | `true` | Автоматически скачать и установить Mihomo, если не найден |
| `mihomo_version` | `latest` | `"latest"` или конкретный тег |

Блок `core_autoupdate` — обновление **уже установленных** ядер:

| Ключ | По умолчанию | Описание |
| :--- | :--- | :--- |
| `enabled` | `true` | Мастер-выключатель проверки обновлений ядер на старте |
| `auto_apply` | `true` | `true` — обновлять без вопросов, `false` — спрашивать подтверждение |
| `check_interval_hours` | `24` | Как часто проверять (`0` = каждый запуск) |
| `telethon` | `true` | Тумблер на Telethon |
| `xray` | `true` | Тумблер на Xray-core |
| `mihomo` | `true` | Тумблер на Mihomo |
| `telethon_max_version` | `2.0.0` | Строгая верхняя граница версии Telethon (2.x = несовместимый rewrite). Пустая строка снимает ограничение |

```json
"core_autoupdate": {
    "enabled": true,
    "auto_apply": true,
    "check_interval_hours": 24,
    "telethon": true,
    "xray": true,
    "mihomo": true,
    "telethon_max_version": "2.0.0"
}
```

## Агрегатор

| Ключ | По умолчанию | Описание |
| :--- | :--- | :--- |
| `agg_countries` | `[]` | Список ISO2-кодов стран для предфильтра агрегатора (например `["RU","DE","GB"]`) |
| `sources` | `{}` | Источники агрегатора, переехали в отдельный `sources.json` |

---

## MTProto

Отдельный блок настроек Telegram proxy checker. Подробности режима — в [docs/mtproto.md](mtproto.md).

| Ключ | Описание |
| :--- | :--- |
| `enabled` | Включен ли MTProto режим |
| `api_id`, `api_hash` | Telegram API credentials для Telethon |
| `threads` | Число параллельных MTProto проверок |
| `timeout` | Таймаут MTProto probe в секундах |
| `max_ping_ms` | Отдельный ping-порог для MTProto |
| `dc_probe_limit` | Сколько лучших Telegram DC пробовать для одного MTProto proxy |
| `crypto_backend` | Режим crypto backend: `auto` / `safe` / `unsafe` |
| `probe_policy` | Политика проверки: `strict`, `balanced` или `telegram_like` |
| `connect_retries` | Число повторов для MTProto connect при временных сетевых сбоях |
| `rpc_retries` | Число повторов Telegram RPC probe после успешного connect |
| `fetch_promo_data` | Запрашивать `help.getPromoData` для живых Telegram proxy |
| `promo_session_file` | Telethon session-файл авторизованного аккаунта, по умолчанию `mtproto_promo` |
| `promo_output_file` | JSON sidecar с полными promo-данными, например `sortedMtproto.promo.json` |
| `promo_threads` | Сколько promo-запросов делать параллельно после проверки live proxy |
| `promo_timeout` | Отдельный таймаут promo-запроса в секундах |
| `promo_probe_limit` | Сколько live proxy обогащать promo-данными (`0` = все) |
| `save_connect_only` | Сохранять `CONN` в отдельный sidecar-файл |
| `connect_only_output_file` | Куда писать `CONN`, например `sortedMtproto.conn.txt` |
| `debug_attempts` | Писать подробный лог попыток |
| `attempts_output_file` | Файл лога попыток, например `sortedMtproto.attempts.json` |
| `output_file` | Основной output-файл для `LIVE`, например `sortedMtproto.txt` |

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
  "probe_policy": "balanced",
  "connect_retries": 1,
  "rpc_retries": 1,
  "fetch_promo_data": true,
  "promo_session_file": "mtproto_promo",
  "promo_output_file": "sortedMtproto.promo.json",
  "promo_threads": 3,
  "promo_timeout": 6,
  "promo_probe_limit": 50,
  "save_connect_only": true,
  "connect_only_output_file": "sortedMtproto.conn.txt",
  "debug_attempts": false,
  "attempts_output_file": "sortedMtproto.attempts.json",
  "output_file": "sortedMtproto.txt"
}
```

> ⚠️ `api_id` и `api_hash` лежат в `config.json` в открытом виде.
