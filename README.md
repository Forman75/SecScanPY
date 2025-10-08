# SecScan — лёгкий статический анализатор безопасности Python-проектов 🛡️🔎

**Кратко:**
SecScan — автономный инструмент (GUI + CLI) для быстрого статического анализа Python-проектов и текстовых конфигов. Ищет возможные утечки секретов (ключи, пароли, JWT и т.п.) и рискованные конструкции/вызовы (например, `pickle.loads`, `yaml.load` без `SafeLoader`, `subprocess.run(..., shell=True)`, `requests(..., verify=False)`). Работает без внешних зависимостей — только стандартная библиотека Python.

---

## 🔥 Что делает SecScan

* Ищет **хардкод-секреты** и токены в `.py`, `.env`, `.json`, `.yml/.yaml`, `.ini`, `.cfg`, `.txt`.
* Проводит **AST-анализ** Python-файлов (импорты, вызовы функций, аргументы) и находит рискованные вызовы.
* Классифицирует находки по уровням риска: **HIGH / MEDIUM / LOW / INFO**.
* Отображает результаты в GUI (Tkinter) с подсветкой и позволяет сохранить JSON-отчёт.
* В комплекте — генератор демо-проекта с уязвимыми примерами для теста.

---

## ⚙️ Быстрый старт

### Требования

* Python 3.7+ (рекомендуется 3.8+).
* Никаких внешних пакетов — используется только стандартная библиотека.

### Запуск GUI

```bash
python main.py
```

### Запуск в CLI

```bash
python main.py --cli /путь/к/проекту --show-snippet --max-bytes 1048576 --out report.json
```

---

## 🧭 Как пользоваться (GUI)

1. Запустите `python main.py`.
2. Нажмите **Выбрать…** и укажите папку проекта или отдельный файл.
3. Включите/выключите **Показывать сниппеты**, при необходимости поменяйте лимит размера файла.
4. Нажмите **Сканировать** — результаты появятся в окне.
5. При желании — **Сохранить отчёт (JSON)**.
6. Кнопка **Сделать демо-проект** создаст `demo_secscan/` с примером уязвимого кода.

---

## 📄 Формат JSON-отчёта

Отчёт включает:

* `scanned_root` — путь, который просканирован;
* `files_count` — количество обработанных файлов;
* `findings_count` — количество найденных проблем;
* `summary` — подсчёт по уровням риска;
* `findings` — массив объектов: `{ file, line, col, rule_id, severity, message, snippet }`.

Пример записи в `findings`:

```json
{
  "file": "demo_secscan/vuln_example.py",
  "line": 10,
  "col": 4,
  "rule_id": "CALL:subprocess.run",
  "severity": "HIGH",
  "message": "subprocess.run с shell=True повышает риск командной инъекции",
  "snippet": "subprocess.run(cmd, shell=True)"
}
```

---

## 🧩 Что проверяется (ключевые правила)

* Регулярные выражения для поиска приватных ключей, API-ключей (AWS/GCP), slack-токенов, JWT, хардкод-паролей.
* Рискованные импорты: `subprocess`, `pickle`, `yaml`, `urllib3`, `hashlib` и др.
* Опасные вызовы: `pickle.load(s)`, `yaml.load(...)` без Loader, `subprocess.run(..., shell=True)`, `requests(..., verify=False)`, `urllib3.disable_warnings()`.

---

## 🔒 Почему это важно (коротко)

Небезопасная десериализация (`pickle`), загрузка YAML без `safe_load`, выполнение команд через shell и отключение проверок TLS — всё это распространённые источники уязвимостей (RCE, командные инъекции, MITM, утечки секретов). SecScan помогает быстро найти такие проблемные места в кодовой базе.

---

## 🧪 Демо-проект

GUI содержит кнопку **Сделать демо-проект** — создаётся папка `demo_secscan/` с:

* `vuln_example.py` (пример небезопасных вызовов и хардкод-секретов),
* `.env`, `config.yml` (фейковые токены).
  Используйте его для проверки и демонстрации.

---

## ⚠️ Ограничения и предупреждение

* SecScan выполняет **статический анализ** — все находки нужно проверять вручную.
* Инструмент предназначен для **образовательных и аудиторских целей**. Не используйте его против чужих систем без разрешения.


---
---


# SecScan — Lightweight Static Security Scanner for Python Projects 🛡️🔎

**Short description:**
SecScan is a small standalone tool (GUI + CLI) for quick static security scanning of Python projects and text configs. It detects possible secret leaks (keys, passwords, JWTs, etc.) and risky constructs/calls (e.g., `pickle.loads`, `yaml.load` without `SafeLoader`, `subprocess.run(..., shell=True)`, `requests(..., verify=False)`). Runs with Python standard library only — no third-party dependencies required.

---

## 🔥 Features

* Detects hardcoded secrets and tokens in `.py`, `.env`, `.json`, `.yml/.yaml`, `.ini`, `.cfg`, `.txt`.
* Performs AST analysis of Python files (imports, function calls, kwargs) to identify contextual risks.
* Categorizes findings by severity: **HIGH / MEDIUM / LOW / INFO**.
* GUI (Tkinter) with colorized output and JSON report export.
* Built-in demo generator with sample vulnerable code.

---

## ⚙️ Quick start

### Requirements

* Python 3.7+ (3.8+ recommended).
* No external packages.

### Run GUI

```bash
python main.py
```

### Run CLI

```bash
python main.py --cli /path/to/project --show-snippet --max-bytes 1048576 --out report.json
```

---

## 🧭 GUI usage

1. Start `python main.py`.
2. Click **Choose…** and select a folder or a file.
3. Toggle **Show snippets** and adjust file size limit if needed.
4. Click **Scan** — results will appear in the window.
5. Optionally **Save report (JSON)**.
6. Use **Create demo project** to generate `demo_secscan/` with vulnerable examples.

---

## 📄 JSON report format

Report contains:

* `scanned_root` — scanned path;
* `files_count` — number of scanned files;
* `findings_count` — total findings;
* `summary` — counts per severity;
* `findings` — array of `{ file, line, col, rule_id, severity, message, snippet }`.

Example:

```json
{
  "file": "demo_secscan/vuln_example.py",
  "line": 10,
  "col": 4,
  "rule_id": "CALL:subprocess.run",
  "severity": "HIGH",
  "message": "subprocess.run with shell=True increases risk of command injection",
  "snippet": "subprocess.run(cmd, shell=True)"
}
```

---

## 🔍 What is scanned (high level)

* Regex patterns for private keys, API keys (AWS/GCP), Slack tokens, JWTs, hardcoded passwords.
* Risky imports: `subprocess`, `pickle`, `yaml`, `urllib3`, `hashlib`, etc.
* Dangerous calls: `pickle.load(s)`, `yaml.load(...)` without Loader, `subprocess.run(..., shell=True)`, `requests(..., verify=False)`, `urllib3.disable_warnings()`.

---

## 🔒 Why it matters

Unsafe deserialization (`pickle`), YAML loading without `safe_load`, executing shell commands with user input, and disabling TLS verification are common sources of vulnerabilities (RCE, command injection, MITM, secret leakage). SecScan provides a quick way to detect such spots in codebases.

---

## 🧪 Demo project

The GUI includes **Create demo project** — generates `demo_secscan/` with:

* `vuln_example.py` (unsafe calls and hardcoded secrets),
* `.env`, `config.yml` (fake tokens).
  Use it to test and demonstrate functionality.

---

## ⚠️ Limitations & Disclaimer

* SecScan is a **static analysis** helper — findings are potential issues and must be manually validated.
* Intended for educational and auditing use. Do not use it against systems you do not have permission to test.

---
