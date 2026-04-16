# Changelog

Почти все изменения проекта будут документироваться в этом файле.

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
