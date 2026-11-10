import json
import tempfile
import unittest
from pathlib import Path

from codesentry.core import ScanError, import_sarif, scan_directory, scan_python, to_sarif


class CoreTests(unittest.TestCase):
    def test_ast_flags_without_execution(self):
        source = b"import subprocess, pickle, hashlib\nsubprocess.run('echo test', shell=True)\npickle.loads(data)\nhashlib.md5(data)\n"
        findings, issues = scan_python(source, "fixture.py")
        self.assertEqual(issues, [])
        self.assertEqual({f["rule_id"] for f in findings}, {"CS001", "CS002", "CS004"})
        self.assertEqual(findings[0]["line"], 2)

    def test_dynamic_sql_and_path(self):
        source = b"cursor.execute(f'SELECT * FROM x WHERE id={value}')\nopen(request.args['path'])\n"
        findings, _ = scan_python(source, "fixture.py")
        self.assertEqual({f["rule_id"] for f in findings}, {"CS003", "CS005"})

    def test_syntax_error_does_not_run_code(self):
        findings, issues = scan_python(b"this is not python ???", "broken.py")
        self.assertEqual(findings, [])
        self.assertEqual(len(issues), 1)

    def test_directory_scope_and_sarif_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "fixture.py").write_text("import os\nos.system('echo test')\n")
            (root / "link.py").symlink_to(root / "fixture.py")
            report = scan_directory(root)
        self.assertEqual(report["files_examined"], 1)
        sarif = to_sarif(report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "CS001")

    def test_js_ts_sarif_import(self):
        document = {"version": "2.1.0", "runs": [{"results": [{"ruleId": "external-1",
            "message": {"text": "secret=nonfunctional-test"}, "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/app.ts"}, "region": {"startLine": 5}}}]}]}]}
        imported = import_sarif(json.dumps(document).encode())
        self.assertEqual(imported["findings"][0]["path"], "src/app.ts")
        self.assertNotIn("nonfunctional-test", json.dumps(imported))


if __name__ == "__main__":
    unittest.main()
