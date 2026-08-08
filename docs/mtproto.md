# 📱 MTProto Mode

MTProto checker работает **отдельно** от Xray/Mihomo:

- принимает только `tg://proxy?...` и `t.me/proxy?...`;
- использует `Telethon` и Telegram API credentials из `config.json`;
- поддерживает обычные MTProxy secrets, `dd`-варианты и `ee/FakeTLS`;
- автоматически ранжирует несколько Telegram DC по месту запуска checker и пробует лучшие из них;
- для `standard/dd` перебирает несколько MTProto transport-режимов, а для `ee` использует отдельный FakeTLS backend;
- сортирует результаты только по ping;
- не делает speed-test;
- показывает отдельные статусы `LIVE / CONN / DROP / UNREACH / SOFT / FAIL`;
- показывает найденный `Promo` статус/канал в live-логе и таблице результатов;
- пишет `LIVE` в основной файл (`sortedMtproto.txt` по умолчанию), `CONN` при `save_connect_only=true` складывает в sidecar `sortedMtproto.conn.txt`, а promo-данные при `fetch_promo_data=true` пишет в `promo_output_file`.

## Запуск

```bash
# MTProto checker по файлу
python v2rayChecker.py --mtproto -f "mtproto.txt"

# MTProto checker по прямой ссылке
python v2rayChecker.py --mtproto -u "tg://proxy?server=1.2.3.4&port=443&secret=0123456789abcdef0123456789abcdef"

# Проверка именно живых MTProto proxy без ping-фильтра
python v2rayChecker.py --mtproto -f "mtproto.txt" --max-ping 0
```

Для проверки именно живых MTProto proxy, а не только быстрых, ставь `MTProto ping = 0` или `--max-ping 0`. Если укажешь `--speed` или `--sort speed` вместе с `--mtproto`, режим будет принудительно возвращён к ping-сортировке с предупреждением.

---

## Статусы

Грубая интерпретация:

| Статус | Что значит |
| :--- | :--- |
| `LIVE` | Proxy прошёл MTProto connect и Telegram RPC probe |
| `CONN` | Transport/connect сработал, но Telegram RPC probe не завершился; это отдельный connect-only результат, а не `FAIL` |
| `DROP` | Proxy живой, но отфильтрован по `max_ping_ms` |
| `UNREACH` | До proxy не удалось поднять даже сырой TCP connect с текущей машины |
| `SOFT` | Proxy TCP-доступен, но MTProto connect/handshake сорвался на ошибке, которую checker не считает окончательным доказательством смерти proxy |
| `FAIL` | Proxy не прошёл connect / handshake / probe |

Если `save_connect_only=true`, sidecar `sortedMtproto.conn.txt` хранит `CONN`-результаты отдельно от основного `sortedMtproto.txt`.

---

## probe_policy

Управляет тем, насколько агрессивно checker делает connect/RPC retries и fallback-проверки:

- `strict` — самый консервативный режим, ближе всего к текущей строгой логике.
- `balanced` — умеренные retries и ограниченные fallback-проверки без лишнего шума.
- `telegram_like` — поведение ближе к Telegram-клиентам, с более терпимыми retry/route сценариями.

`connect_retries` и `rpc_retries` задают маленькие bounded retry-бюджеты, чтобы длинные списки не раздували runtime.

Для современных `ee/FakeTLS` proxy checker использует TDLib-style ClientHello и TLS-record handoff: fake TLS handshake bytes не смешиваются с MTProto payload.

---

## MTProto Promo

`help.getPromoData` требует авторизованную пользовательскую Telethon session. Без неё checker покажет `Promo: auth required`, а не будет считать proxy плохим. Для создания session один раз запусти:

```bash
python v2rayChecker.py --mtproto-login

# Если Telegram напрямую недоступен, можно логиниться через конкретный MTProxy:
python v2rayChecker.py --mtproto-login -u "tg://proxy?server=1.2.3.4&port=443&secret=..."
```

То же доступно в TUI: `Настройки` → `Login MTProto`. При входе checker спросит телефон, код Telegram и, если на аккаунте включена 2FA, пароль. В активных сессиях Telegram этот вход подписывается как `MK_XrayChecker`.

Перед login checker показывает ToS-подтверждение: использовать только свой аккаунт, не применять данные для спама/скама, AI/data scraping или обхода правил Telegram. По умолчанию promo enrichment ограничен `promo_threads=3` и `promo_probe_limit=50`; если нужен полный список, поставь `promo_probe_limit=0`, но это повышает нагрузку на аккаунт.

`promo_output_file` хранит JSON-массив результатов с `proxy`, `label`, `status`, `ping_ms` и `promo_data`. В `promo_data` нормализуются `status`, `display`, `title`, `username`, `peer_id`, `psa_type`, `psa_message`, `expires`, `proxy`, `error`, а также найденные `chats` / `users`.

---

## Настройка

Полное описание ключей блока `mtproto` — в [docs/config.md](config.md#mtproto). Пример:

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
