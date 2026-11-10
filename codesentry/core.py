"""Bounded Python AST heuristics and cautious SARIF exchange."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
from pathlib import Path

MAX_SOURCE = 1024 * 1024
MAX_SARIF = 8 * 1024 * 1024
MAX_FILES = 5000
MAX_ENTRIES = 20000
MAX_TOTAL = 100 * 1024 * 1024
RULES = {
    "CS001": ("CWE-78", "Command execution API or shell mode requires source review"),
    "CS002": ("CWE-502", "Deserialization API may be unsafe for untrusted input"),
    "CS003": ("CWE-89", "Dynamic SQL construction requires parameterization review"),
    "CS004": ("CWE-327", "Legacy hash algorithm requires cryptographic-use review"),
    "CS005": ("CWE-22", "Possible user-controlled filesystem path requires containment review"),
}


class ScanError(ValueError):
    pass


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    return ""


def _is_dynamic_sql(node: ast.AST) -> bool:
    return (isinstance(node, ast.JoinedStr)
            or isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
            or isinstance(node, ast.Call) and _name(node.func).endswith(".format"))


def _is_user_path(node: ast.AST) -> bool:
    return any(isinstance(part, ast.Name) and part.id in {"request", "input", "argv"}
               for part in ast.walk(node))


def scan_python(raw: bytes, relative_path: str) -> tuple[list[dict], list[str]]:
    if len(raw) > MAX_SOURCE:
        raise ScanError("source exceeds 1 MiB")
    try:
        source = raw.decode("utf-8")
        tree = ast.parse(source, filename=relative_path)
    except (UnicodeDecodeError, SyntaxError, RecursionError) as exc:
        return [], [f"{relative_path}: cannot parse Python source ({type(exc).__name__})"]
    file_hash = hashlib.sha256(raw).hexdigest()
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func)
        matched = []
        if name in {"os.system", "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_output"}:
            if name == "os.system" or any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                                           and keyword.value.value is True for keyword in node.keywords):
                matched.append("CS001")
        if name in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "yaml.load"}:
            matched.append("CS002")
        if name.endswith(".execute") and node.args and _is_dynamic_sql(node.args[0]):
            matched.append("CS003")
        if name in {"hashlib.md5", "hashlib.sha1"}:
            matched.append("CS004")
        if name in {"open", "Path", "pathlib.Path"} and node.args and _is_user_path(node.args[0]):
            matched.append("CS005")
        for rule_id in matched:
            cwe, message = RULES[rule_id]
            findings.append({"rule_id": rule_id, "cwe": cwe, "path": relative_path,
                             "line": node.lineno, "file_sha256": file_hash,
                             "interpretation": message + "; heuristic, exploitability not established",
                             "origin": "python_ast"})
    return findings, []


def scan_directory(root: Path) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise ScanError("scope must be a real directory")
    root = root.resolve(strict=True)
    findings = []
    issues = []
    files = 0
    entries = 0
    total_bytes = 0
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        here = Path(current)
        directories[:] = sorted(name for name in directories if name not in {".git", ".venv", "node_modules", "__pycache__"}
                                and not (here / name).is_symlink()
                                and len((here / name).relative_to(root).parts) <= 12)
        entries += len(directories) + len(names)
        if entries > MAX_ENTRIES:
            raise ScanError("directory entry count exceeds 20000")
        for name in sorted(names):
            path = here / name
            if path.suffix != ".py" or path.is_symlink():
                continue
            files += 1
            if files > MAX_FILES:
                raise ScanError("Python file count exceeds 5000")
            relative = path.relative_to(root).as_posix()
            try:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        continue
                    raw = stream.read(MAX_SOURCE + 1)
            except OSError:
                issues.append(f"{relative}: unreadable file")
                continue
            if len(raw) > MAX_SOURCE:
                issues.append(f"{relative}: source exceeds 1 MiB")
                continue
            total_bytes += len(raw)
            if total_bytes > MAX_TOTAL:
                raise ScanError("total Python source exceeds 100 MiB")
            found, notes = scan_python(raw, relative)
            findings.extend(found)
            issues.extend(notes)
            if len(findings) > 10000:
                raise ScanError("finding count exceeds 10000")
    return {"schema_version": 1, "root": str(root), "files_examined": files,
            "findings": findings, "issues": issues,
            "interpretation": "heuristic source patterns; no code execution or exploit validation"}


def import_sarif(raw: bytes) -> dict:
    if not 0 < len(raw) <= MAX_SARIF:
        raise ScanError("SARIF import must be 1 to 8 MiB")
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise ScanError("invalid SARIF JSON") from exc
    if not isinstance(document, dict) or document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
        raise ScanError("expected SARIF 2.1.0 runs")
    findings = []
    issues = []
    for run in document["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            issues.append("invalid SARIF run")
            continue
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            locations = result.get("locations", [])
            if not isinstance(locations, list) or not locations:
                issues.append("result without physical source location")
                continue
            physical = locations[0].get("physicalLocation", {}) if isinstance(locations[0], dict) else {}
            if not isinstance(physical, dict):
                issues.append("invalid SARIF physical location")
                continue
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            path = artifact.get("uri") if isinstance(artifact, dict) else None
            line = region.get("startLine") if isinstance(region, dict) else None
            if not isinstance(path, str) or not path.endswith((".js", ".jsx", ".ts", ".tsx")) or not isinstance(line, int) or line < 1:
                issues.append("unsupported SARIF location")
                continue
            findings.append({"rule_id": str(result.get("ruleId", "external"))[:128],
                             "path": path[:1024], "line": line, "origin": "external_sarif",
                             "interpretation": "imported third-party finding; upstream validation and severity not verified"})
            if len(findings) > 10000:
                raise ScanError("SARIF finding count exceeds 10000")
    return {"source_sha256": hashlib.sha256(raw).hexdigest(), "findings": findings, "issues": issues,
            "validation": "external analyzer results imported; source code not executed"}


def to_sarif(report: dict) -> dict:
    results = []
    for finding in report["findings"]:
        results.append({"ruleId": finding["rule_id"], "message": {"text": finding["interpretation"]},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["path"]},
                                                            "region": {"startLine": finding["line"]}}}],
                        "properties": {"cwe": finding.get("cwe"), "origin": finding["origin"]}})
    rules = [{"id": rule_id, "shortDescription": {"text": description},
              "properties": {"tags": [cwe]}} for rule_id, (cwe, description) in RULES.items()]
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "CodeSentry", "rules": rules}}, "results": results}]}
