# CodeSentry validation report

Date: 2026-11-09. Only isolated, nonfunctional test source was analyzed.

| Check | Actual result |
| --- | --- |
| Python compilation | Passed |
| `python3 -m unittest discover -s tests -v` | 5 passed, 0 failed, 0 skipped |
| Python AST indicators and source line references | Unit tested |
| SARIF 2.1.0 export and JS/TS SARIF import | Unit tested with isolated data; full schema validation not run |
| Semgrep, real repository scan, exploitability validation | Not run or not implemented |
| Ruff/pytest | Unavailable in documented environment |

Next: test against authorized repositories, compare with established SAST tools, add false-positive review, and validate SARIF against the official schema. No precision or detection coverage metric has been measured.
