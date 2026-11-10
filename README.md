# CodeSentry

CodeSentry's first milestone is an offline static review of authorized Python source. It parses Python ASTs without importing or executing the code, reports bounded heuristic indicators for shell execution, deserialization, dynamic SQL, legacy hashes, and potentially user-controlled paths, and exports SARIF 2.1.0. It can also import JS/TS findings from an external SARIF-producing analyzer. It does **not** parse JavaScript/TypeScript itself or claim those imported findings are verified.

## Run

Python 3.12+ and the standard library are sufficient:

```bash
PYTHONPATH=. python3.12 -m codesentry.cli /path/to/authorized/source --format json > report.json
PYTHONPATH=. python3.12 -m codesentry.cli /path/to/authorized/source --import-sarif /path/to/js-ts-results.sarif --format sarif > results.sarif
python3.12 -m unittest discover -s tests -v
```

The scanner skips symlinks and common dependency directories, caps source files at 1 MiB, the scan at 5,000 Python files/20,000 entries/100 MiB source, and findings at 10,000. It emits path, line, source SHA-256, CWE mapping, and an explanation; it does not include source snippets. Imported SARIF messages are discarded to avoid printing secrets in untrusted analyzer output. SARIF output follows the [OASIS 2.1.0 structure](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).

All `CS` findings are **heuristic review cues**, not proof of exploitability. AST checks can miss aliases, dataflow, framework-specific behavior, and safe sanitization. The source parser uses the standard [Python `ast` module](https://docs.python.org/3/library/ast.html). No external Semgrep installation or scan was available here.

## Next milestone

Add a documented Semgrep adapter behind explicit executable/rule configuration, validate against authorized repositories, build false-positive triage with audit records, and add secure authenticated reporting. See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [VALIDATION_REPORT.md](VALIDATION_REPORT.md).
