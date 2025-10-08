import ast
import argparse
import json
import os
import re
import sys
import threading
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Константы и правила:
TEXT_EXTS = {".env", ".txt", ".ini", ".cfg", ".conf", ".json", ".yml", ".yaml"}
PY_EXT = ".py"
SECRET_PATTERNS: Dict[str, Tuple[str, str]] = {
    "SECRET:PRIVATE_KEY_BLOCK": (r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", "HIGH"),
    "SECRET:GENERIC_API_KEY": (r"(?i)\b(api[_-]?key|secret|token|access[_-]?key|auth[_-]?token)\b\s*[:=]\s*['\"][^'\"\n]{8,}['\"]", "HIGH"),
    "SECRET:PASSWORD_ASSIGN": (r"(?i)\b(pass|password|pwd)\b\s*[:=]\s*['\"][^'\"\n]{6,}['\"]", "HIGH"),
    "SECRET:AWS_ACCESS_KEY_ID": (r"\bAKIA[0-9A-Z]{16}\b", "HIGH"),
    "SECRET:AWS_SECRET_ACCESS_KEY": (r"(?i)aws(.{0,20})?(secret|access)\s*key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]", "HIGH"),
    "SECRET:GCP_API_KEY": (r"\bAIza[0-9A-Za-z\-_]{35}\b", "HIGH"),
    "SECRET:SLACK_TOKEN": (r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b", "HIGH"),
    "SECRET:JWT": (r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "MEDIUM"),
    "SECRET:EMAIL": (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "INFO"),
    "SECRET:IPV4": (r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", "INFO"),
}

RISKY_IMPORTS: Dict[str, Tuple[str, str]] = {
    "subprocess": ("Импорт subprocess: потенциально опасные системные вызовы", "MEDIUM"),
    "pickle": ("Импорт pickle: небезопасная десериализация", "MEDIUM"),
    "yaml": ("Импорт yaml: возможна небезопасная загрузка (yaml.load)", "LOW"),
    "ftplib": ("Импорт ftplib: передача данных в открытом виде", "LOW"),
    "paramiko": ("Импорт paramiko: проверьте безопасные настройки SSH", "INFO"),
    "urllib3": ("Импорт urllib3: возможное отключение проверки SSL", "LOW"),
    "hashlib": ("Импорт hashlib: проверьте использование md5/sha1", "INFO"),
}

RISKY_CALLS: Dict[Tuple[Optional[str], str], Tuple[str, str]] = {
    ("pickle", "load"): ("pickle.load: небезопасная десериализация из файла", "HIGH"),
    ("pickle", "loads"): ("pickle.loads: небезопасная десериализация из строки/сети", "HIGH"),
    ("yaml", "load"): ("yaml.load без SafeLoader: потенциальная RCE", "HIGH"),
    ("subprocess", "Popen"): ("subprocess.Popen с shell=True повышает риск командной инъекции", "HIGH"),
    ("subprocess", "call"): ("subprocess.call с shell=True повышает риск командной инъекции", "HIGH"),
    ("subprocess", "run"): ("subprocess.run с shell=True повышает риск командной инъекции", "HIGH"),
    ("requests", "get"): ("requests.* c verify=False отключает проверку сертификата TLS", "MEDIUM"),
    ("requests", "post"): ("requests.* c verify=False отключает проверку сертификата TLS", "MEDIUM"),
    ("requests", "put"): ("requests.* c verify=False отключает проверку сертификата TLS", "MEDIUM"),
    ("requests", "delete"): ("requests.* c verify=False отключает проверку сертификата TLS", "MEDIUM"),
    ("urllib3", "disable_warnings"): ("urllib3.disable_warnings: маскирует предупреждения TLS", "LOW"),
}

SEV_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Дата-классы:
@dataclass
class Finding:
    file: str
    line: int
    col: int
    rule_id: str
    severity: str
    message: str
    snippet: Optional[str] = None

# Движок сканирования:
def _kw_bool(kwargs: Dict[str, Any], name: str, default=None):
    v = kwargs.get(name, default)
    if isinstance(v, bool):
        return v
    return None

class RiskyAstVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, show_snippet: bool, source_text: str):
        self.filename = filename
        self.show_snippet = show_snippet
        self.source_text = source_text
        self.findings: List[Finding] = []
        self.aliases: Dict[str, str] = {}

    def _add(self, node: ast.AST, rule_id: str, severity: str, message: str):
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0)
        snippet = None
        if self.show_snippet:
            try:
                snippet = ast.get_source_segment(self.source_text, node)
            except Exception:
                snippet = None
        self.findings.append(Finding(self.filename, line, col, rule_id, severity, message, snippet))

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod = alias.name.split(".")[0]
            asname = alias.asname or mod
            self.aliases[asname] = mod
            if mod in RISKY_IMPORTS:
                msg, sev = RISKY_IMPORTS[mod]
                self._add(node, f"IMPORT:{mod}", sev, msg)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = (node.module or "").split(".")[0]
        for alias in node.names:
            asname = alias.asname or alias.name
            self.aliases[asname] = mod or alias.name
        if mod in RISKY_IMPORTS:
            msg, sev = RISKY_IMPORTS[mod]
            self._add(node, f"IMPORT:{mod}", sev, msg)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        mod_name = None
        func_name = None

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                base = node.func.value.id
                mod_name = self.aliases.get(base, base)
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        kwargs: Dict[str, Any] = {}
        for kw in node.keywords or []:
            if kw.arg is not None:
                if isinstance(kw.value, ast.Constant):
                    kwargs[kw.arg] = kw.value.value
                else:
                    kwargs[kw.arg] = None

        if (mod_name, func_name) == ("yaml", "load"):
            has_loader = any(k == "Loader" for k in kwargs)
            if not has_loader:
                msg, sev = RISKY_CALLS[("yaml", "load")]
                self._add(node, "CALL:yaml.load", sev, msg)

        if mod_name == "subprocess" and func_name in {"Popen", "call", "run"}:
            if _kw_bool(kwargs, "shell", default=False) is True:
                msg, sev = RISKY_CALLS[("subprocess", func_name)]
                self._add(node, f"CALL:subprocess.{func_name}", sev, msg)

        if mod_name == "requests" and func_name in {"get", "post", "put", "delete", "head", "patch"}:
            if _kw_bool(kwargs, "verify", default=True) is False:
                self._add(node, f"CALL:requests.{func_name}", "MEDIUM",
                          "requests.* c verify=False отключает проверку сертификата TLS")

        if (mod_name, func_name) == ("urllib3", "disable_warnings"):
            msg, sev = RISKY_CALLS[("urllib3", "disable_warnings")]
            self._add(node, "CALL:urllib3.disable_warnings", sev, msg)

        if mod_name == "pickle" and func_name in {"load", "loads"}:
            msg, sev = RISKY_CALLS[("pickle", func_name)]
            self._add(node, f"CALL:pickle.{func_name}", sev, msg)

        if mod_name == "hashlib" and func_name in {"md5", "sha1"}:
            self._add(node, f"CALL:hashlib.{func_name}", "LOW",
                      f"hashlib.{func_name} считается криптографически слабым")

        self.generic_visit(node)

def read_text_safe(p: Path) -> Optional[str]:
    try:
        data = p.read_bytes()
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="ignore")
    except Exception:
        return None

def scan_text_for_secrets(path: Path, text: str, show_snippet: bool) -> List[Finding]:
    findings: List[Finding] = []
    for rule_id, (pattern, severity) in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, text):
            start = m.start()
            line = text.count("\n", 0, start) + 1
            col = start - text.rfind("\n", 0, start)
            snippet = None
            if show_snippet:
                span = text[max(0, start - 80): m.end() + 80]
                snippet = span.replace("\n", " ")
            findings.append(Finding(str(path), line, col, rule_id, severity, "Найден потенциальный секрет", snippet))
    return findings

def scan_python_ast(path: Path, text: str, show_snippet: bool) -> List[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        return [Finding(str(path), e.lineno or 1, e.offset or 0, "PARSE:SYNTAX_ERROR", "INFO",
                        f"Не удалось разобрать AST: {e.msg}")]
    v = RiskyAstVisitor(str(path), show_snippet, text)
    v.visit(tree)
    return v.findings

def iter_candidate_files(root: Path, max_bytes: int) -> List[Path]:
    files: List[Path] = []
    if root.is_file():
        if root.suffix.lower() in TEXT_EXTS.union({PY_EXT}) and root.stat().st_size <= max_bytes:
            return [root]
        return []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        try:
            if (ext == PY_EXT or ext in TEXT_EXTS) and p.stat().st_size <= max_bytes:
                files.append(p)
        except OSError:
            pass
    return files

def scan_path(root: Path, max_bytes: int, show_snippet: bool) -> Tuple[List[Finding], List[Path]]:
    files = iter_candidate_files(root, max_bytes)
    all_findings: List[Finding] = []
    for f in files:
        text = read_text_safe(f)
        if text is None:
            continue
        all_findings.extend(scan_text_for_secrets(f, text, show_snippet))
        if f.suffix.lower() == PY_EXT:
            all_findings.extend(scan_python_ast(f, text, show_snippet))
    all_findings.sort(key=lambda x: (-SEV_ORDER.get(x.severity, 0), x.file, x.line))
    return all_findings, files


# GUI:
class SecScanGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecScan — статический анализ (Python + секреты)")
        self.geometry("980x640")

        # Переменные
        self.path_var = tk.StringVar()
        self.max_bytes_var = tk.IntVar(value=1_048_576)
        self.snippet_var = tk.BooleanVar(value=True)

        # Верхняя панель
        frm_top = ttk.Frame(self, padding=8)
        frm_top.pack(fill="x")

        ttk.Label(frm_top, text="Путь к проекту/файлу:").pack(side="left")
        self.entry_path = ttk.Entry(frm_top, textvariable=self.path_var, width=70)
        self.entry_path.pack(side="left", padx=6)
        ttk.Button(frm_top, text="Выбрать…", command=self.choose_path).pack(side="left")
        ttk.Button(frm_top, text="Сканировать", command=self.run_scan_threaded).pack(side="left", padx=6)

        # Опции
        frm_opts = ttk.Frame(self, padding=8)
        frm_opts.pack(fill="x")
        ttk.Checkbutton(frm_opts, text="Показывать сниппеты", variable=self.snippet_var).pack(side="left")
        ttk.Label(frm_opts, text="Лимит размера файла (байт):").pack(side="left", padx=(16, 4))
        ttk.Entry(frm_opts, textvariable=self.max_bytes_var, width=12).pack(side="left")
        ttk.Button(frm_opts, text="Сохранить отчёт (JSON)", command=self.save_report).pack(side="right")
        ttk.Button(frm_opts, text="Сделать демо-проект", command=self.create_demo_project).pack(side="right", padx=6)

        # Текстовый вывод
        frm_out = ttk.Frame(self, padding=(8, 0, 8, 8))
        frm_out.pack(fill="both", expand=True)

        self.txt = tk.Text(frm_out, wrap="none")
        self.txt.pack(fill="both", expand=True, side="left")
        yscroll = ttk.Scrollbar(frm_out, orient="vertical", command=self.txt.yview)
        yscroll.pack(side="right", fill="y")
        self.txt.configure(yscrollcommand=yscroll.set)
        xscroll = ttk.Scrollbar(self, orient="horizontal", command=self.txt.xview)
        xscroll.pack(fill="x")
        self.txt.configure(xscrollcommand=xscroll.set)

        # Цветовые теги
        self.txt.tag_config("HIGH", foreground="#b00020", font=("TkDefaultFont", 9, "bold"))
        self.txt.tag_config("MEDIUM", foreground="#d35400")
        self.txt.tag_config("LOW", foreground="#6c757d")
        self.txt.tag_config("INFO", foreground="#0d6efd")

        # Данные отчёта для сохранения
        self.last_report: Optional[Dict[str, Any]] = None

    # Вспомогательные методы GUI:
    def choose_path(self):
        p = filedialog.askdirectory(title="Выберите папку проекта")
        if not p:
            p = filedialog.askopenfilename(title="…или выберите файл")
        if p:
            self.path_var.set(p)

    def append_line(self, line: str, sev: Optional[str] = None):
        end = self.txt.index("end-1c")
        self.txt.insert("end", line + "\n")
        if sev:
            self.txt.tag_add(sev, f"{end} linestart", f"{end} lineend")
        self.txt.see("end")

    def clear_output(self):
        self.txt.delete("1.0", "end")

    def run_scan_threaded(self):
        t = threading.Thread(target=self.run_scan, daemon=True)
        t.start()

    def run_scan(self):
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("Внимание", "Укажите путь к проекту или файлу.")
            return
        root = Path(path)
        if not root.exists():
            messagebox.showerror("Ошибка", f"Путь не найден: {root}")
            return

        show_snippet = bool(self.snippet_var.get())
        max_bytes = int(self.max_bytes_var.get())

        self.clear_output()
        self.append_line(f"▶ Сканирование: {root}")
        self.append_line(f"   Опции: show_snippet={show_snippet}, max_bytes={max_bytes}")

        try:
            findings, files = scan_path(root, max_bytes, show_snippet)
        except Exception as e:
            messagebox.showerror("Ошибка сканирования", str(e))
            return

        self.append_line("")
        self.append_line(f"📦 Просканировано файлов: {len(files)}")
        self.append_line(f"⚠ Найдено потенциальных проблем: {len(findings)}\n")

        summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1
            loc = f"{f.file}:{f.line}"
            sev = f"[{f.severity}]"
            self.append_line(f"{sev:>8} {loc:<40} {f.rule_id} — {f.message}", f.severity)
            if show_snippet and f.snippet:
                sn = f.snippet.strip()
                if len(sn) > 200:
                    sn = sn[:200] + " …"
                self.append_line(f"         ↳ {sn}")

        self.append_line("\nИтоги по уровням: " + json.dumps(summary, ensure_ascii=False))

        # Сохраняем данные для отчёта:
        self.last_report = {
            "scanned_root": str(root.resolve()),
            "files_count": len(files),
            "findings_count": len(findings),
            "summary": summary,
            "findings": [asdict(f) for f in findings],
        }

    def save_report(self):
        if not self.last_report:
            messagebox.showinfo("Отчёт", "Пока нечего сохранять — выполните сканирование.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            title="Сохранить отчёт"
        )
        if not path:
            return
        try:
            Path(path).write_text(json.dumps(self.last_report, ensure_ascii=False, indent=2), encoding="utf-8")
            messagebox.showinfo("Отчёт", f"Отчёт сохранён в:\n{path}")
        except Exception as e:
            messagebox.showerror("Ошибка записи", str(e))

    def create_demo_project(self):
        base = Path.cwd() / "demo_secscan"
        try:
            base.mkdir(exist_ok=True)
            # 1) Уязвимый Python
            (base / "vuln_example.py").write_text(
                '''import subprocess, pickle, hashlib, yaml, requests, urllib3

password = "SuperSecret123"  # hardcoded password
AWS_KEY = "AKIAABCDEFGHIJKLMNOP"  # looks like an AWS Access Key ID

def run_cmd(cmd):
    # Небезопасно: shell=True
    subprocess.run(cmd, shell=True)

def unsafe_pickle(data):
    return pickle.loads(data)

def weak_hash(data):
    return hashlib.md5(data).hexdigest()

def yaml_bad_load(s):
    return yaml.load(s)  # без SafeLoader

def insecure_request(url):
    urllib3.disable_warnings()
    return requests.get(url, verify=False)
''',
                encoding="utf-8"
            )
            # 2) .env
            (base / ".env").write_text(
                'API_KEY="abcdEFGHijklMNOPqrstUVWX12345678"\nPASSWORD="qwerty123"\n',
                encoding="utf-8"
            )
            # 3) config.yml
            (base / "config.yml").write_text(
                "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaabbbbbccccc.ddddeeefff\n",
                encoding="utf-8"
            )
            messagebox.showinfo("Демо-проект", f"Создана папка:\n{base}\n\nВыберите её и запустите сканирование.")
            # Автоподстановка пути
            self.path_var.set(str(base))
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать демо-проект: {e}")


# main
def main_cli():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--cli", action="store_true", help="Запуск без GUI, только CLI")
    ap.add_argument("path", nargs="?", help="Путь к проекту/файлу")
    ap.add_argument("--max-bytes", type=int, default=1_048_576)
    ap.add_argument("--show-snippet", action="store_true")
    ap.add_argument("--out", help="Сохранить отчёт в JSON")
    args, _ = ap.parse_known_args()

    if args.cli:
        if not args.path:
            print("Укажите путь. Пример: python secscan_gui.py --cli ./project", file=sys.stderr)
            sys.exit(2)
        root = Path(args.path)
        findings, files = scan_path(root, args.max_bytes, args.show_snippet)
        print(f"Просканировано: {len(files)} файлов. Найдено: {len(findings)} проблем.")
        summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1
            loc = f"{f.file}:{f.line}"
            print(f"[{f.severity}] {loc:<40} {f.rule_id} — {f.message}")
            if args.show_snippet and f.snippet:
                sn = f.snippet.strip()
                if len(sn) > 200: sn = sn[:200] + " …"
                print("         ↳", sn)
        print("Итоги:", summary)
        if args.out:
            payload = {
                "scanned_root": str(root.resolve()),
                "files_count": len(files),
                "findings_count": len(findings),
                "summary": summary,
                "findings": [asdict(f) for f in findings],
            }
            Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            print("Отчёт:", args.out)
        return
    app = SecScanGUI()
    app.mainloop()
if __name__ == "__main__":
    main_cli()
