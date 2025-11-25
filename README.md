
<div align="center">

# 🕷️ MK_XRAYchecker 🕷️

**Мощный, многопоточный чекер прокси V2Ray/Xray**  
*Быстро. Жестко. Эффективно.* - все как я люблю.

<p>
  <a href="https://github.com/MKultra6969/MK_XRAYchecker">
    <img src="https://img.shields.io/badge/VERSION-0.7-magenta?style=for-the-badge&logo=python" alt="Version">
  </a>
  <a href="http://www.wtfpl.net/">
    <img src="https://img.shields.io/badge/LICENSE-WTFPL-red?style=for-the-badge" alt="License">
  </a>
  <a href="https://t.me/MKextera">
    <img src="https://img.shields.io/badge/Telegram-MKextera-blue?style=for-the-badge&logo=telegram" alt="Telegram">
  </a>
</p>

```
+═════════════════════════════════════════════════════════════════════════+
║      ███▄ ▄███▓ ██ ▄█▀ █    ██  ██▓    ▄▄▄█████▓ ██▀███   ▄▄▄           ║
║     ▓██▒▀█▀ ██▒ ██▄█▒  ██  ▓██▒▓██▒    ▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄         ║
║     ▓██    ▓██░▓███▄░ ▓██  ▒██░▒██░    ▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄       ║
║     ▒██    ▒██ ▓██ █▄ ▓▓█  ░██░▒██░    ░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██      ║
║     ▒██▒   ░██▒▒██▒ █▄▒▒█████▓ ░██████▒  ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒     ║
║     ░ ▒░   ░  ░▒ ▒▒ ▓▒░▒▓▒ ▒ ▒ ░ ▒░▓  ░  ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░     ║
║     ░  ░      ░░ ░▒ ▒░░░▒░ ░ ░ ░ ░ ▒  ░    ░      ░▒ ░ ▒░  ▒   ▒▒ ░     ║
║     ░      ░   ░ ░░ ░  ░░░ ░ ░   ░ ░     ░        ░░   ░   ░   ▒        ║
║            ░   ░  ░      ░         ░  ░            ░           ░  ░     ║
║                                                                         ║
+═════════════════════════════════════════════════════════════════════════+
║                               MKultra69                                 ║
+═════════════════════════════════════════════════════════════════════════+
    
```

</div>

## ⚡ Описание

**MK_XRAYchecker** — Утилита на Python для массовой проверки доступности и задержки V2Ray/Xray прокси. Скрипт парсит конфиги из файлов или URL (Например GitHub Raw), декодирует Base64 (и другие форматы), создает временные конфиги и проверяет их через реальное ядро Xray.

### 🔥 Возможности
*   **Поддержка протоколов:** `VMess`, `VLESS`, `Trojan`, `Shadowsocks`, `Hysteria2`.
*   **Парсинг:** Извлекает прокси из "каши" текста, Base64 строк, ссылок-подписок. 
    - (Ну, то есть скрипту практически похуй в каком виде ты скормишь ему ссылки.)
*   **Скорость:** Многопоточная проверка (Thread Pool) UP TO 1337 THREADS.
*   **Режимы работы:** Красивое меню или CLI аргументы.
*   **Сортировка:** Автоматически сортирует рабочие прокси по пингу.

---

## ⚠️ ВАЖНО: Установка ядра (Xray core)

Для работы скрипта **НЕОБХОДИМО** наличие исполняемого файла ядра Xray или V2Ray. Скрипт использует его как "движок" для проверки соединения.

### 🛠️ Инструкция:
1.  Перейди в репозиторий **Xray-core**:  
    👉 **[https://github.com/XTLS/Xray-core/releases](https://github.com/XTLS/Xray-core/releases)**
2.  Скачай архив, подходящий для твоей ОС (например, `Xray-windows-64.zip` для Windows).
3.  Распакуй архив.
4.  **Скопируй файл `xray.exe` (или `xray` на Linux/Mac) в папку, где лежит скрипт `v2rayChecker.py`.**

> 📂 **Структура папки должна выглядеть так:**
> - `v2rayChecker.py`
> - `xray.exe` (или папка bin/xray.exe)
> - `requirements.txt`

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

**Режим командной строки (примеры):**
```bash
# Проверка из файла
python v2rayChecker.py -f "proxies.txt"

# Проверка по ссылке-подписке
python v2rayChecker.py -u "https://example.com/sub"

# Указать количество потоков и таймаут
python v2rayChecker.py -f "list.txt" -T 50 -t 2
```

---

## ⚙️ Аргументы cli

| Аргумент | Описание |
| :--- | :--- |
| `-f`, `--file` | Путь к файлу с прокси (.txt) |
| `-u`, `--url` | URL ссылка на подписку или список |
| `-o`, `--output` | Файл для сохранения рабочих проксей (по дефолту: `sortedProxy.txt`) |
| `-T`, `--threads` | Количество потоков (по дефолту: 20) |
| `-t`, `--timeout` | Таймаут ожидания ответа в секундах (по дефолту: 3) |
| `--reuse` | Перепроверить файл результатов (`sortedProxy.txt`) |
| `-s`, `--shuffle` | Перемешать список перед проверкой |

---

## 💀 Credits & License

**Ваш покорный:** [MKultra69](https://github.com/MKultra6969)  
**Веб:** [mk69.su](http://mk69.su)

### 📜 License
Проект КАК ВСЕГДА распространяется под лицензией **WTFPL** (Do What The Fuck You Want To Public License).
