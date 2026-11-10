from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import MAX_SARIF, ScanError, import_sarif, scan_directory, to_sarif


def main() -> None:
    parser = argparse.ArgumentParser(prog="codesentry")
    parser.add_argument("root", type=Path, help="explicitly authorized Python source directory")
    parser.add_argument("--import-sarif", type=Path, action="append", default=[], help="external JS/TS SARIF results")
    parser.add_argument("--format", choices=("json", "sarif"), default="json")
    args = parser.parse_args()
    try:
        report = scan_directory(args.root)
        for path in args.import_sarif:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SARIF:
                raise ScanError("SARIF input must be a regular file of at most 8 MiB")
            imported = import_sarif(path.read_bytes())
            report["findings"].extend(imported["findings"])
            report["issues"].extend(imported["issues"])
        output = to_sarif(report) if args.format == "sarif" else report
    except (ScanError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
