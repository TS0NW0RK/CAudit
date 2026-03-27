#!/usr/bin/env python3
# создано с помощью дикпика(кто понял тот понял) и кривых русских ручек разработчика
import os
import sys
import json
import hashlib
import time
import logging
import argparse
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

import ollama

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logging.warning("no watchdog.skipping.")

HAS_LIBCLANG = False
clang = None

def find_libclang(extra_path=None):
    global clang, HAS_LIBCLANG
    try:
        import clang.cindex as cindex
        clang = cindex
    except ImportError:
        logging.warning("clang module not installed. Install with: pip install clang")
        return False

    try:
        clang.Index.create()
        return True
    except Exception:
        pass

    paths_to_try = []
    files_to_try = []

    script_dir = os.path.dirname(os.path.abspath(__file__))
    paths_to_try.append(script_dir)
    files_to_try.append(os.path.join(script_dir, 'libclang.dylib'))
    files_to_try.append(os.path.join(script_dir, 'libclang.so'))

    if extra_path:
        paths_to_try.append(extra_path)
        files_to_try.append(os.path.join(extra_path, 'libclang.dylib'))
        files_to_try.append(os.path.join(extra_path, 'libclang.so'))

    possible_paths = [
        '/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib',
        '/Library/Developer/CommandLineTools/usr/lib',
        '/usr/lib/llvm-14/lib',
        '/usr/lib/llvm-15/lib',
        '/usr/lib/x86_64-linux-gnu',
        '/usr/lib64/llvm',
    ]
    for p in possible_paths:
        paths_to_try.append(p)
        files_to_try.append(os.path.join(p, 'libclang.dylib'))
        files_to_try.append(os.path.join(p, 'libclang.so'))

    for path in paths_to_try:
        libfile = os.path.join(path, 'libclang.dylib')
        if not os.path.exists(libfile):
            libfile = os.path.join(path, 'libclang.so')
            if not os.path.exists(libfile):
                continue
        try:
            clang.Config.set_library_path(path)
            clang.Index.create()
            logging.info(f"libclang found and initialized using directory: {path}")
            return True
        except Exception as e:
            logging.debug(f"Failed with path {path}: {e}")

    for full_path in files_to_try:
        if not os.path.exists(full_path):
            continue
        try:
            clang.Config.set_library_file(full_path)
            clang.Index.create()
            logging.info(f"libclang found and initialized using file: {full_path}")
            return True
        except Exception as e:
            logging.debug(f"Failed with file {full_path}: {e}")

    logging.warning("libclang not found or not working. Fallback to text parser.")
    return False

DEFAULT_MODEL = "carstenuhlig/omnicoder-9b:q8_0   "
DEFAULT_SCAN_DIR = "./Applications/PosterBoard.app/"
DEFAULT_RESULTS_FILE = "vuln_results.json"
DEFAULT_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".m", ".mm"}
DEFAULT_SCAN_INTERVAL = 5
DEFAULT_IGNORE_DIRS = {".git", "__pycache__", "build", "dist", "node_modules"}
DEFAULT_MAX_FUNC_SIZE = 32000
MAX_RETRIES = 2
LANG_MAP = {
    ".c": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".h": "C/C++",
    ".hpp": "C++",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
}

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ResultCache:
    def __init__(self, filename: str):
        self.filename = filename
        self.data: Dict[str, List[Dict]] = {}
        self.load()

    def load(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
                logger.info(f"loaded {len(self.data)} from cache.")
            except Exception as e:
                logger.error(f"error loading cache: {e}")
                self.data = {}

    def save(self):
        try:
            with open(self.filename, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"error saving cache: {e}")

    def get(self, filepath: str, content_hash: str) -> Optional[List[Dict]]:
        key = f"{filepath}:{content_hash}"
        return self.data.get(key)

    def set(self, filepath: str, content_hash: str, vulns: List[Dict]):
        key = f"{filepath}:{content_hash}"
        self.data[key] = vulns
        self.save()


def get_code_snippet(filepath: str, start_line: int, end_line: int) -> str:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        if start_line < 1 or end_line > len(lines):
            return ""
        return ''.join(lines[start_line-1:end_line])
    except Exception:
        return ""


def extract_functions_libclang(filepath: str) -> List[str]:
    if not HAS_LIBCLANG:
        return []
    try:
        index = clang.Index.create()
        tu = index.parse(filepath)
        functions = []
        def visit(node):
            if node.kind in (clang.CursorKind.FUNCTION_DECL,
                             clang.CursorKind.CXX_METHOD,
                             clang.CursorKind.OBJC_INSTANCE_METHOD_DECL,
                             clang.CursorKind.OBJC_CLASS_METHOD_DECL,
                             clang.CursorKind.FUNCTION_TEMPLATE,
                             clang.CursorKind.CONSTRUCTOR,
                             clang.CursorKind.DESTRUCTOR):
                if node.extent.start.line > 0 and node.extent.end.line > 0:
                    if node.is_definition():
                        start = node.extent.start.line
                        end = node.extent.end.line
                        code = get_code_snippet(filepath, start, end)
                        if code.strip():
                            functions.append(code)
            for child in node.get_children():
                visit(child)
        visit(tu.cursor)
        return functions
    except Exception as e:
        logger.error(f"libclang extraction failed for {filepath}: {e}")
        return []


def extract_functions_text(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"cannot read file {filepath}: {e}")
        return []

    functions = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i].strip()
        if line and not line.startswith(('//', '#', '/*')):
            if '(' in line and ')' in line:
                brace_pos = line.find('{')
                if brace_pos == -1:
                    j = i + 1
                    while j < n and '{' not in lines[j]:
                        j += 1
                    if j < n:
                        brace_pos = j
                    else:
                        i += 1
                        continue
                start_line = i
                brace_count = 0
                found_opening = False
                for k in range(start_line, n):
                    line_k = lines[k]
                    if not found_opening:
                        if '{' in line_k:
                            found_opening = True
                            brace_count += line_k.count('{')
                    if found_opening:
                        brace_count += line_k.count('{') - line_k.count('}')
                        if brace_count == 0:
                            end_line = k
                            func_text = ''.join(lines[start_line:end_line+1])
                            functions.append(func_text.strip())
                            i = end_line + 1
                            break
                else:
                    i += 1
            else:
                i += 1
        else:
            i += 1

    if not functions:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            full_content = f.read()
        if full_content.strip():
            functions = [full_content]
    return functions


def extract_functions(filepath: str) -> List[str]:
    if HAS_LIBCLANG:
        funcs = extract_functions_libclang(filepath)
        if funcs:
            return funcs
        else:
            logger.debug(f"No functions found with libclang in {filepath}, falling back to text parser.")
    return extract_functions_text(filepath)


def build_prompt(code: str, language: str) -> str:
    return f"""
You are an expert security researcher specializing in low-level vulnerabilities in {language} for XNU/iOS/macOS.

Your task: Analyze the provided code and **ONLY** report vulnerabilities that you are **100% certain** exist. 
Do NOT report:
- Potential issues that depend on external factors.
- Hypothetical vulnerabilities without clear exploitability.
- Code style or maintainability issues (like hardcoded values) unless they directly cause a security flaw.
- Generic warnings like "missing null check" unless it can be proven to cause a crash or exploit.


For each **real, exploitable vulnerability**, provide:
- "type": The vulnerability class (e.g., buffer overflow, use-after-free, race condition, format string).
- "description": A concise explanation of why this is a security issue, including the exact code location and how it could be exploited.
- "location": The line number(s) or code snippet.
- "severity": "High", "Medium", or "Low" (only High if clearly exploitable).
- "mitigation": Concrete fix recommendation.

If there are no 100% certain vulnerabilities, output {{"vulnerabilities": []}}.

**Output only valid JSON** with the key "vulnerabilities". Do not include any explanations outside the JSON.


Code: {code}


"""


def extract_json_from_text(text: str) -> Optional[str]:
    patterns = [
        r'```json\s*(\{.*?\})\s*```',
        r'```\s*(\{.*?\})\s*```',
        r'(\{.*\})'
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def parse_llm_response(response_text: str) -> List[Dict]:
    json_str = extract_json_from_text(response_text)
    if not json_str:
        start = response_text.find('{')
        end = response_text.rfind('}')
        if start != -1 and end != -1 and end > start:
            json_str = response_text[start:end+1]
        else:
            logger.warning("cant find json in the answer")
            return []

    try:
        data = json.loads(json_str)
        return data.get('vulnerabilities', [])
    except json.JSONDecodeError as e:
        logger.error(f"error parsing json: {e}\n")
        return []


def analyze_with_llm(code: str, language: str, model: str, retry: int = 0) -> List[Dict]:
    prompt = build_prompt(code, language)
    try:
        response = ollama.chat(model=model, messages=[{'role': 'user', 'content': prompt}])
        text = response['message']['content']
        vulns = parse_llm_response(text)
        if vulns is not None:
            return vulns
        else:
            if retry < MAX_RETRIES:
                stricter_prompt = prompt + "\n\nREMEMBER: Output ONLY the JSON object, nothing else."
                response = ollama.chat(model=model, messages=[{'role': 'user', 'content': stricter_prompt}])
                text = response['message']['content']
                vulns = parse_llm_response(text)
                if vulns:
                    return vulns
            return []
    except Exception as e:
        return []


def analyze_file(filepath: str, cache: ResultCache, model: str, force: bool = False):
    filepath = os.path.abspath(filepath)
    try:
        with open(filepath, 'rb') as f:
            content_hash = hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return

    if not force:
        cached = cache.get(filepath, content_hash)
        if cached is not None:
            return

    ext = os.path.splitext(filepath)[1].lower()
    language = LANG_MAP.get(ext, "C/C++/Objective-C")

    functions = extract_functions(filepath)

    all_vulns = []
    for idx, func in enumerate(functions):
        if len(func) > DEFAULT_MAX_FUNC_SIZE:
            func = func[:DEFAULT_MAX_FUNC_SIZE]
        vulns = analyze_with_llm(func, language, model)
        for v in vulns:
            v['file'] = filepath
            v['block_index'] = idx
        all_vulns.extend(vulns)

    cache.set(filepath, content_hash, all_vulns)


def should_ignore(path: str, ignore_dirs: set) -> bool:
    parts = Path(path).parts
    for part in parts:
        if part in ignore_dirs:
            return True
    return False


def scan_directory(directory: str, cache: ResultCache, model: str, extensions: set, ignore_dirs: set):
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in extensions:
                filepath = os.path.join(root, file)
                if not should_ignore(filepath, ignore_dirs):
                    analyze_file(filepath, cache, model)


def periodic_scan(directory: str, cache: ResultCache, model: str, extensions: set,
                  ignore_dirs: set, interval: int):
    while True:
        try:
            scan_directory(directory, cache, model, extensions, ignore_dirs)
            time.sleep(interval)
        except KeyboardInterrupt:
            break
        except Exception as e:
            time.sleep(interval)


if WATCHDOG_AVAILABLE:
    class CodeChangeHandler(FileSystemEventHandler):
        def __init__(self, cache: ResultCache, model: str, extensions: set, ignore_dirs: set):
            self.cache = cache
            self.model = model
            self.extensions = extensions
            self.ignore_dirs = ignore_dirs

        def on_modified(self, event):
            if not event.is_directory and self._is_relevant(event.src_path):
                logger.info(f"File modified: {event.src_path}")
                analyze_file(event.src_path, self.cache, self.model, force=True)

        def on_created(self, event):
            if not event.is_directory and self._is_relevant(event.src_path):
                logger.info(f"File created: {event.src_path}")
                analyze_file(event.src_path, self.cache, self.model)

        def _is_relevant(self, path):
            ext = os.path.splitext(path)[1].lower()
            return ext in self.extensions and not should_ignore(path, self.ignore_dirs)


def main():
    parser = argparse.ArgumentParser(description=".")
    parser.add_argument("directory", nargs="?", default=DEFAULT_SCAN_DIR,
                        help=f"Directory to scan (default: {DEFAULT_SCAN_DIR})")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Ollama model (default: {DEFAULT_MODEL})")
    parser.add_argument("--results", default=DEFAULT_RESULTS_FILE,
                        help=f"File to store results (default: {DEFAULT_RESULTS_FILE})")
    parser.add_argument("--watchdog", action="store_true", default=False,
                        help="Use watchdog for file change monitoring (if installed)")
    parser.add_argument("--interval", type=int, default=DEFAULT_SCAN_INTERVAL,
                        help=f"Periodic scan interval in seconds (default: {DEFAULT_SCAN_INTERVAL})")
    parser.add_argument("--extensions", nargs="+", default=list(DEFAULT_EXTENSIONS),
                        help="File extensions to analyze (default: .c .cpp .h .m etc.)")
    parser.add_argument("--ignore-dirs", nargs="+", default=list(DEFAULT_IGNORE_DIRS),
                        help="Directories to ignore (default: .git __pycache__ etc.)")
    parser.add_argument("--libclang-path", default=None,
                        help="Path to directory containing libclang.dylib (e.g., /usr/lib/llvm-14/lib)")
    args = parser.parse_args()

    global HAS_LIBCLANG, clang
    if find_libclang(extra_path=args.libclang_path):
        HAS_LIBCLANG = True
    else:
        HAS_LIBCLANG = False

    extensions = {ext if ext.startswith('.') else '.' + ext for ext in args.extensions}
    ignore_dirs = set(args.ignore_dirs)

    try:
        ollama.list()
    except Exception as e:
        logger.error(f"Cannot connect to Ollama: {e}")
        sys.exit(1)

    cache = ResultCache(args.results)

    scan_directory(args.directory, cache, args.model, extensions, ignore_dirs)

    if args.watchdog and WATCHDOG_AVAILABLE:
        handler = CodeChangeHandler(cache, args.model, extensions, ignore_dirs)
        observer = Observer()
        observer.schedule(handler, args.directory, recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
