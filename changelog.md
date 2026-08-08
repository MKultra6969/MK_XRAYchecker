# Changelog

Почти все изменения проекта будут документироваться в этом файле.

## [1.9.0] - 2026-08-09

### Added
- Автообновление всех трёх ядер, от версий которых зависит checker: **Telethon** (MTProto), **Xray-core** и **Mihomo**. Проверка выполняется на старте, до основной работы, и по умолчанию раз в 24 часа (`core_update.state.json` хранит время последней проверки).
- Новый блок `core_autoupdate` в `config.json` с мастер-выключателем и отдельными тумблерами на каждое ядро: `enabled`, `auto_apply`, `check_interval_hours`, `telethon`, `xray`, `mihomo`, `telethon_max_version`.
- Пункт меню `Настройки → Ядра: автообновление`: включение/отключение автообновления целиком и по каждому ядру, переключение `auto`/`ask`, интервал проверки, потолок версии Telethon, ручная проверка «Проверить сейчас» и таблица «Версии ядер» (установлено / доступно / статус).
- Строка `Автообновление ядер` в статус-панели интерактивного меню.
- CLI: `--update-cores` (принудительно проверить и обновить ядра, затем выйти) и `--no-core-update` (пропустить только обновление ядер, оставив self-update скрипта). Переменная окружения `MKXRAY_SKIP_CORE_UPDATE=1` делает то же самое.
- `xray_installer.py`: детект установленной версии Mihomo (`get_current_mihomo_version`), поиск установленного ядра (`find_installed_core`), проверка обновления (`check_for_core_update`) и обновление бинарника (`update_core_binary`) — общие для Xray и Mihomo.

### Changed
- Обновление ядра выполняется только для уже установленного бинарника; первичная установка по-прежнему за `autoinstall_xray` / `autoinstall_mihomo`, так что скрипт не тянет ядро, которым пользователь не пользуется.
- Если бинарник ядра лежал не в `bin/`, а рядом со скриптом, после обновления синхронизируются оба расположения — иначе checker продолжал бы подхватывать старую копию.
- `xray_installer._safe_print` больше не падает на legacy-консоли Windows (cp1252): раньше перехватывался только `ImportError`, и `UnicodeEncodeError` из `rich` пробивался наружу.

### Fixed
- Обновление Telethon ограничено сверху веткой `1.x` (`telethon_max_version = "2.0.0"`). Telethon 2.x — несовместимый rewrite API, и `mtproto_checker` / `mtproto_faketls` на нём не работают: `mtproto_faketls` импортирует `telethon.network.connection.tcpmtproxy`, которого в 2.x нет. Ограничение снимается пустым значением.
- Каждое обновление откатывается при провале проверки: бинарники Xray/Mihomo бэкапятся перед заменой и восстанавливаются, если новый бинарник не отвечает на запрос версии; Telethon переустанавливается на прошлую версию, если после `pip install` не проходит импорт `telethon` + `mtproto_faketls` + `mtproto_checker`.
- После успешного обновления Telethon скрипт перезапускается автоматически: старый модуль уже импортирован в процесс, и без рестарта новая версия не применилась бы (защита от цикла — `MKXRAY_CORE_UPDATE_RESTARTED`).

## [1.8.1] - 2026-08-06

### Fixed
- MTProto checker больше не выбрасывает живые Telegram proxy в `DROP`: `ping_ms` для MTProto — это полное время установки сессии (FakeTLS handshake + генерация auth_key + `help.getConfig`), то есть штатные 3-8 секунд, и сравнивать его с дефолтным `max_ping_ms = 666` было бессмысленно. Теперь `max_ping_ms` фильтрует по чистому TCP RTT до прокси (`tcp_ping_ms`), а handshake остаётся только для отображения и сортировки.
- Для `ee`-секретов (FakeTLS) первым теперь пробуется `faketls-randomized` — единственный packet codec, который принимает настоящий MTProxy; `faketls-abridged` и `faketls-intermediate` оставлены фолбэком для форков. Раньше живой прокси сжигал `(connect_retries + 1) * 2` заведомо мёртвых коннекта на каждый DC перед рабочим транспортом (~18 с при `probe_policy = telegram_like`).
- Настоящая ошибка транспорта больше не теряется: Telethon глотает исключение в `MTProtoSender._try_connect` и отдаёт generic `Connection to Telegram failed N time(s)`. Теперь checker перехватывает исходное исключение и показывает причину (`FakeTLS server hello verification failed`, `Unexpected first TLS record type`, `Proxy closed the connection after sending initial payload` и т.д.).

### Changed
- В live-логе MTProto рядом с временем handshake выводится TCP RTT: `[LIVE] 62.84.121.63:8443 | 4182ms (tcp 1ms)`.
- `tcp_ping_ms` добавлен в sidecar-диагностику `sortedMtproto.attempts.json` и `sortedMtproto.promo.json`.
- Подсказки о фильтре ping в MTProto-режиме уточнены: фильтруется TCP RTT, а не время MTProto handshake.
- В `requirements.txt` для Telethon задан минимум `>=1.44.0`. Telethon 1.43+ мигрирует `mtproto_promo.session` со схемы v7 на v8 (колонка `tmp_auth_key`) прямо при открытии, и старый Telethon после этого падает с `ValueError: too many values to unpack (expected 5)`. Без нижней границы `pip install -r requirements.txt` не обновлял уже установленный старый Telethon.

## [1.8.0] - 2026-07-24

### Added
- Обновлены Xray-конфиги для совместимости с 26.3.27 и 26.7.11, добавлены возможности Mihomo 1.19.29 и Hysteria 2.10, поддержка AnyTLS и TUIC. #14
- Добавлен официальный импорт Mihomo-форматов SSR, Hysteria1, SOCKS, аутентифицированных HTTP(S) и mierus, включая нативный passthrough YAML-прокси. #14

### Changed
- Capability routing теперь выбирает подходящее ядро Xray или Mihomo для каждого прокси. #14
- Улучшены валидация парсера и каноническая дедупликация; исправлены runtime/native mappings и удалён `allowInsecure`. #14

## [1.7.0] - 2026-07-04

### Added
- Добавлено автоисправление Xray-батчей: при ошибке сборки outbound скрипт извлекает тег из лога ядра, отбрасывает только проблемный прокси и повторяет запуск batch-а. #14, refs #15
- Обновлена генерация Xray/Mihomo-конфигов для современных параметров ссылок: `spx`/`spiderX`, `pqv`, `pcs`, `packetEncoding`, `ed`, `ech`, Hysteria2 `obfsPassword` и `alpn`. #14

### Changed
- Дедупликация входных ссылок теперь использует канонический ключ по распарсенной proxy-структуре, поэтому порядок query-параметров, мусорные параметры и fragment/tag больше не создают дубликаты. #14

## [1.6.4] - 2026-05-27

### Fixed
- Исправлена проверка Shadowsocks через Mihomo: `ss://` ссылки больше не пропускаются из-за рассинхрона `shadowsocks`/`ss` при генерации Mihomo-конфига. #13
- Для Shadowsocks разделены allowlist шифров Xray и Mihomo: Xray по-прежнему отбрасывает legacy cipher'ы, чтобы избежать `Exit 23`, а Mihomo принимает поддерживаемые `aes-*-cfb`, `rc4-md5`, `chacha20-ietf` и другие совместимые методы. #13

## [1.6.3] - 2026-05-25

### Changed
- Автоматическое распределение прокси по ядрам: теперь скрипт автоматически использует ядро `mihomo` для сканирования прокси Hysteria2 (`hy2://`, `hysteria2://`), даже если основным выбрано ядро `xray`.

## [1.6.2] - 2026-05-25

### Added
- Добавлено предупреждение (алерт) о несовместимости протокола Hysteria2 с ядром Xray. Скрипт теперь рекомендует переключиться на ядро Mihomo, если в списке есть Hysteria2 ссылки, а текущее ядро - Xray.

## [1.6.1] - 2026-05-24

### Fixed
- Исправлено падение (TypeError: `>` not supported between instances of `NoneType` and `int`) при неудачном замере скорости скачивания.
- Удален нерабочий сервис загрузки логов `paste.mk69.su`, теперь всегда используется `paste.rs`.

## [1.6.0] - 2026-05-20

### Added
- MTProto checker теперь умеет читать `help.getPromoData` для живых Telegram proxy и показывает результат в live-логе, колонке `Promo`, summary и sidecar JSON `sortedMtproto.promo.json`.
- Добавлен авторизованный promo-session flow: CLI `--mtproto-login` и TUI-пункт `Настройки -> Login MTProto` создают Telethon session `mtproto_promo.session`, поддерживают код Telegram и 2FA-пароль.
- Вход в Telegram подписывается как `MK_XrayChecker` в active sessions.
- Для promo enrichment добавлены настройки `fetch_promo_data`, `promo_session_file`, `promo_output_file`, `promo_threads`, `promo_timeout` и `promo_probe_limit`.
- Promo enrichment распараллелен через in-memory `StringSession`, чтобы не шарить SQLite session-файл между параллельными Telethon clients.

### Changed
- `help.getPromoData` больше не вызывается внутри unauthenticated liveness probe: сначала checker определяет `LIVE`, затем отдельным authenticated enrichment добавляет promo metadata.
- Без авторизованной session promo теперь отображается как `auth required`, а не как шумный `AuthKeyUnregisteredError`.
- Дефолты promo сделаны консервативнее: `promo_threads=3`, `promo_timeout=6`, `promo_probe_limit=50`; `promo_threads` ограничен максимумом 8.
- Promo targets при лимите сортируются по `ping_ms`, чтобы сначала проверять самые быстрые live proxy.
- Перед `--mtproto-login` добавлено явное ToS-подтверждение: свой аккаунт, без spam/scam и AI/data scraping.

### Fixed
- Убрано последовательное ожидание promo-запросов по всем live proxy: enrichment теперь использует bounded parallelism и отдельный timeout.
- `is_user_authorized()` в promo path теперь ограничен timeout, чтобы зависшие proxy не блокировали весь этап.

## [1.5.0] - 2026-05-20

### Added
- MTProto checker получил `probe_policy` (`strict` / `balanced` / `telegram_like`), ограниченные `connect_retries`/`rpc_retries`, fallback RPC `help.GetNearestDcRequest` после `help.GetConfigRequest` и JSON-диагностику attempts через `debug_attempts`.
- `CONN`/connect-only MTProto результаты теперь могут сохраняться отдельно в sidecar `sortedMtproto.conn.txt`, не смешиваясь с основным `LIVE` output.

### Fixed
- Исправлен FakeTLS `ee` stream handoff: server-handshake `application_data` больше не отдаётся Telethon как MTProto payload, а первый client application-data теперь предваряется TLS `ChangeCipherSpec`, как в TDLib/gotd.
- Обновлён FakeTLS ClientHello под текущий TDLib-style layout с GREASE/permuted extensions, чтобы современные `ee` proxy не падали в ложный `CONN/SOFT`.

### Changed
- Документация MTProto синхронизирована с `MTPROTO_CHECKER_IMPROVEMENT_PLAN.md`: описаны статусы `LIVE / CONN / DROP / UNREACH / SOFT / FAIL`, политики `probe_policy` (`strict`, `balanced`, `telegram_like`), `connect_retries`/`rpc_retries`, `save_connect_only` и sidecar-файл `sortedMtproto.conn.txt`.

## [1.4.1] - 04-15-2026

### Added
- Telegram checker теперь поддерживает `tg://socks` / `t.me/socks`.

### Fixed
- MTProto `safe` mode теперь отключает не только `cryptg`, но и native `libssl` backend Telethon, чтобы битый FakeTLS/MTProto поток не валил процесс через OpenSSL assertion. #9
- Для входящих MTProto пакетов добавлена проверка длины ciphertext перед AES-IGE decrypt, чтобы некратный 16 буфер завершался обычным `FAIL`, а не hard-crash процесса. #9 #7
- Если preferred MTProto DC не сработали, checker теперь автоматически добирает оставшиеся Telegram DC вместо раннего ложного `Timeout/FAIL` на живом proxy. #9
- Известный asyncio-шум `Future exception was never retrieved` для уже обработанного misaligned MTProto ciphertext подавляется, а причина показывается в человекочитаемом виде.
- На Windows подавлен `asyncio Proactor` traceback на `ConnectionResetError [WinError 10054]` во время `_call_connection_lost()`, если это уже обработанное закрытие MTProto transport, а не реальный сбой проверки.
- Telegram checker теперь явно показывает, сколько `proxy`-ссылок было найдено всего, и отдельно считает `MTProto` и `SOCKS`, чтобы mixed-файлы не выглядели как “пропавшие” прокси.
- Для `ee/FakeTLS` checker теперь перебирает несколько MTProxy transport (`randomized`, `intermediate`, `abridged`) вместо жёсткой привязки к одному codec, поэтому живые proxy с нестандартным transport больше не застревают в ложном `CONN`. #9

## [1.4.0] - 04-13-2026

### Changed
- MTProto checker получил управляемый выбор crypto backend: `auto`, `safe` и `unsafe`.
- Новый CLI-флаг `--mtproto-crypto` и новый ключ `mtproto.crypto_backend` в `config.json` позволяют принудительно выбирать backend или оставить авто-режим.
- В интерактивное меню настроек добавлен отдельный пункт выбора MTProto crypto backend.
- Перед стартом MTProto проверки теперь явно показывается, какой crypto backend реально выбран.

### Fixed
- MTProto checker больше не зависит жёстко от проблемного native crypto backend в чужом окружении: auto-режим консервативно уходит в safe path для рискованных сценариев. #7
- Восстановление panic-like ошибок в MTProto path стало надёжнее: создание `TelegramClient` и cleanup-path больше не сваливаются в грубый crash без нормального `FAIL/CONN` результата.

## [1.3.5] - 04-12-2026

### Fixed
- Исправлена регрессия FakeTLS, из-за которой живые `ee` proxy уходили в `dcX/faketls: Timeout` вместо корректной проверки.

## [1.3.4] - 04-11-2026

### Changed
- MTProto checker теперь выделяет сетевую недоступность proxy в отдельный статус `UNREACH`, чтобы сразу отличать недоступный proxy-хост от transport/FakeTLS/DC ошибок.

### Fixed
- Исправлено падение MTProto checker на части `ee/FakeTLS` proxy: первый TLS `application_data` после `ServerHello` больше не теряется, поэтому Telethon не получает сдвинутый MTProto-поток. #7
- MTProto worker больше не валит весь checker на `BaseException`-уровневых ошибках вроде `PanicException` из `cryptg`: connect/probe/disconnect path восстанавливается в нормальный результат проверки. #7
- Сообщение `dcX/faketls: Timeout` больше не маскирует кейс, когда сам proxy-хост недоступен по TCP с текущей машины.

## [1.3.3] - 04-10-2026

### Fixed
- Обновлён FakeTLS `ClientHello` после изменений Telegram MTProto. #6
- Убрана рассинхронизация TLS-потока, которая приводила к падению OpenSSL/AES-IGE и ложным ошибкам MTProto checker.

## [1.3.2] - 03-21-2026

### Added
- Поддержка `hex`, `base64` и `base64url` для `MTProto secret` в `tg://proxy` / `t.me/proxy`.

### Changed
- MTProto parser теперь канонизирует `secret` в `hex`, а live-результаты сохраняются в нормализованном `tg://proxy?...&secret=<hex>` виде.
- Один и тот же MTProto proxy, пришедший в `hex`, `base64` или `base64url`, теперь схлопывается в один `unique_key`.

### Fixed
- Восстановление `+` после query-parsing для обычного `base64` `secret`, чтобы MTProto ссылки не ломались из-за `parse_qs`.
- `dd` MTProto secrets больше не гоняются через неподходящие transport-режимы: checker использует только `randomized`.
- FakeTLS backend теперь корректно принимает `ee` secrets из `hex`, обычного `base64` и `base64url`.

## [1.3.1] - 03-15-2026

### Added
- Новый регрессионный self-test для парсинга subscription URL: проверяет JSON-списки источников и строки с markdown/json-обрамлением. #5
- GitHub issue templates для багов, feature request и вопросов по использованию.

### Changed
- `-f/--file` теперь официально документирован как вход для `.txt` и `.json` со списками подписок и прямых ссылок.

### Fixed
- Исправлен разбор `sources.json` и других JSON-файлов в режиме `--file`: subscription URL больше не уходят в `requests` с хвостами вроде `"` или `",`. #5
- Извлечение HTTP(S)-подписок стало устойчивым к JSON/Markdown-обрамлению и посторонним завершающим символам. #5
- В `fetch_url()` добавлена финальная защитная нормализация URL, чтобы мусорный ввод не превращался в ложные `HTTP 404`. #5

## [1.3.0] - 03-14-2026

### Added
- Локальный helper-модуль `mtproto_faketls.py` для поддержки `ee/FakeTLS` MTProxy без внешнего runtime-wrapper.
- Новый параметр `dc_probe_limit` в блоке `mtproto` для ограничения числа лучших Telegram DC, которые checker перебирает для одного прокси.
- Файл `VERSION` в корне репозитория для fallback-проверки версии через raw GitHub, если Releases API недоступен.

### Changed
- MTProto probe теперь подбирает transport в зависимости от типа секрета (`standard`, `dd`, `ee/FakeTLS`) и перебирает несколько наиболее близких Telegram DC вместо жёсткого фиксированного `dc2`.
- MTProto итоговый вывод теперь разделяет результаты на `LIVE / CONN / DROP / FAIL`, чтобы медленные и частично рабочие прокси не считались одинаковыми ошибками.
- Интерактивное меню переделано в двухуровневый интерфейс: отдельные разделы `Проверка / Настройки / Сервис`, плюс компактная панель текущего состояния.
- Автообновление теперь отслеживает и валидирует новые MTProto-модули через расширенный smoke-check после staged update.
- README обновлён под двухуровневое меню, улучшенный MTProto probe и поведение ping-фильтра.

### Fixed
- Исправлена обработка `dd` MTProxy secrets, из-за которой живые ссылки ошибочно отбрасывались на парсинге.
- Убран шум `Connecting/Disconnecting`, прогресс MTProto перестал ломаться сторонними логами, а хвост `Future exception was never retrieved` больше не засоряет консоль.
- Флаги `--speed` и `--sort speed` для `--mtproto` больше не игнорируются молча: checker явно предупреждает и переключается обратно на ping.
- Smoke-check updater-а больше не считает обновление успешным, если `Telethon` не импортируется и MTProto режим всё равно был бы нерабочим.

## [1.2.0] - 03-14-2026

### Added
- Отдельный `MTProto checker` для Telegram proxy (`tg://proxy`, `t.me/proxy`) в новом модуле `mtproto_checker.py`.
- Новый CLI-флаг `--mtproto` для запуска отдельного MTProto режима без участия `xray/mihomo`.
- Новый блок `mtproto` в `config.json`: `enabled`, `api_id`, `api_hash`, `threads`, `timeout`, `max_ping_ms`, `output_file`.
- Новый пункт `MTProto` в интерактивном меню и отдельная настройка `MTProto ping`.
- Self-test для MTProto parser через `--self-test`.
- Новая зависимость `telethon` в `requirements.txt`.

### Changed
- Логика MTProto вынесена в отдельный backend и orchestration path внутри `v2rayChecker.py`, не смешиваясь с текущим Xray/Mihomo pipeline.
- Для существующих конфигов включено автоматическое дозаполнение новых nested-ключей в `config.json`.
- `--self-test` и автообновление конфига переведены на ASCII-safe вывод, чтобы не падать в Windows-консолях с `cp1252`.
- README обновлён под новый отдельный MTProto режим, отдельный output-файл и требования к `api_id/api_hash`.

### Fixed
- Исправлен сбой `--self-test` и первого запуска после обновления конфига в окружениях с ограниченной консольной кодировкой Windows.

## [1.1.4] - 02-21-2026

### Added
- Новый безопасный режим для роутеров/OpenWRT: `router_mode` в `config.json` и CLI-флаг `--router-mode`.
- Новая политика очистки старых процессов ядра: `core_cleanup_mode` (`owned`/`all`/`none`) и CLI-флаг `--cleanup-mode`.
- Новый фильтр агрегатора по странам: `--agg-country` и ключ конфига `agg_countries`.

### Changed
- Стартовая очистка процессов ядра переведена в безопасный режим по умолчанию (`owned`): убиваются только процессы, запущенные самим чекером.
- Для `router_mode` добавлена защита от агрессивной зачистки: режим `all` автоматически понижается до `owned`.
- Агрегатор сначала пытается фильтровать страны по уже существующим меткам/тегам, и только затем делает GeoIP-lookup для оставшихся IP.

### Fixed
- Исправлен кейс, когда при выборе `mihomo` чекер мог завершать системный `mihomo`, запущенный роутером.

## [1.1.3] - 02-17-2026

### Added
- Поддержка ядра `mihomo` на уровне проекта: выбор режима `auto/xray/mihomo` через CLI (`--engine`) и интерактивное меню.
- Автоустановка `mihomo` в `xray_installer.py` (поиск релиза, выбор ассета под платформу/архитектуру, распаковка `.zip/.tar.gz/.tgz/.gz`, установка в `./bin`).
- Поддержка Clash/Mihomo YAML-подписок (`proxies:`) через `PyYAML` с конвертацией в ссылочный формат для проверки.
- Отсев по ping через `max_ping_ms` / `--max-ping` (значения выше порога автоматически исключаются).

### Changed
- Логика чтения `-f/--file` теперь обрабатывает смешанные входы: прямые ссылки и URL-подписки разворачиваются одновременно.
- Детект и логирование ядра стали прозрачнее: в логе фиксируются `Core detected (...)`, `Engine mode`, режим `mihomo`.
- Для `mihomo` включён режим проверки `1 процесс = 1 прокси`; для `xray` сохранён batch-режим.
- Список прокси перед запуском нормализуется детерминированно (стабильный порядок), добавлены диагностические строки по количеству найденных/добавленных ссылок.

### Fixed
- Исправлен баг, из-за которого URL-подписки в смешанном файле игнорировались, если уже были найдены прямые proxy-ссылки.
- Исправлен конфликт выбора ядра: при явном режиме (`xray`/`mihomo`) больше нет тихого переключения на другое ядро.
- Исправлена обработка subscription URL из файлов: убраны ложные срабатывания на посторонние ссылки внутри описательного текста.
- Улучшена совместимость с транспортами `xhttp/httpupgrade/h2` при обработке и прогоне ссылок.

## [1.1.0] - 01-08-2026

### Added
- Самообновление скрипта через модуль `updater.py`: проверка новых версий через GitHub API (releases/latest) с fallback на raw-файл `VERSION`.
- Staged-обновления `.new` + маркер `update.pending` и автоприменение обновлений при старте через `apply_pending_update_if_any()`.
- Новые ключи конфига (через `DEFAULTCONFIG`): `autoupdate`, `repo_owner`, `repo_name`, `repo_branch`.
- Авто-установка ядра Xray через модуль `xray_installer.py`: определение OS/архитектуры, скачивание релиза Xray-core, распаковка в `./bin`, выставление executable permissions, перенос `geoip.dat/geosite.dat` при наличии.
- Новые ключи конфига для ядра: `autoinstall_xray`, `xray_version` (поддержка `latest` или конкретного тега).
- CLI флаг `--no-update` для пропуска проверки обновлений при запуске.

### Changed
- Стартовый пайплайн: скрипт теперь применяет staged-апдейты до основной логики и выполняет проверку обновлений на старте (если модуль `updater` доступен).
- Детект ядра: если `xray/v2ray` не найден, скрипт пытается автоматически установить Xray и обновить `corepath` в `config.json`.

### Fixed
- Уменьшены ручные шаги при первом запуске на “чистой” машине: при отсутствии ядра предлагается (или выполняется) установка, вместо немедленного выхода с ошибкой.

## [1.0.3] - 01-05-2026

### Added
- Улучшенная нормализация URL в `cleanurl()` с поддержкой HTML entities и URL-encoding (кейсы `&amp;`, `&amp%3B`, `%26amp%3B`).
- CLI флаг `--self-test` для проверки корректности парсинга URL/параметров через `parse_qs()`.
- CLI флаг `--debug` (режим точечного дебага: `proxies_per_batch=1`, `threads=1`).
- Автосохранение артефактов падения батча: `savefailedbatch()` складывает `batch*.json` и `.log.txt` в `./failed_batches` и печатает команду воспроизведения `xray run -test -c ...`.
- Whitelist для Shadowsocks (AEAD-only) и фильтрация ссылок с неподдерживаемыми шифрами, чтобы не ломать запуск Xray. 

### Changed
- Запуск core (`runcore()`): вывод процесса теперь собирается через `stdout=PIPE` и `stderr=STDOUT` вместо глушения stdout.
- Логирование в batch-конфигах: `loglevel` повышен с `none` до `warning` для более информативных ошибок Xray.
- Обработка ошибок старта ядра в `Checker()`: вывод ошибки читается из объединённого потока/через `communicate()`, что снижает случаи `Unknown error`.
- Валидация VLESS REALITY: `pbk` проверяется через base64url-декод (строго 32 байта), `sid` нормализуется/валидируется как hex (чинится нечётная длина), `flow` отбрасывается если `security` не `tls/reality`.

### Fixed
- Исправлен баг, из-за которого параметры `security/pbk/sid/flow/type` не парсились при HTML/URL-экранировании, что приводило к генерации невалидных конфигов.
- Исправлены падения Xray с `Exit: 23`, вызванные невалидными REALITY `pbk` (теперь такие ссылки отбрасываются до генерации outbound).
- Исправлены падения Xray с `Exit: 23` на Shadowsocks из-за устаревших/неподдерживаемых cipher’ов (теперь такие SS-ссылки фильтруются).

## [] - 00-00-0000

### Added

### Changed

### Fixed
