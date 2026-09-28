"""`m6-release-artifact.py docs-inventory`, the bundle-free half of the
executed-guide check, run in hosted CI on every guide change (M6-C219).

The positive case is the real guide; each negative case plants one edit in a
copy and must exit 1 with its own witness, so a green step can go red.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "m6-release-artifact.py"
GUIDE = Path(__file__).resolve().parents[1] / "docs" / "operator.md"


RUNTIME = GUIDE.with_name("runtime.md")


def inventory(guide, *extra):
    return subprocess.run([sys.executable, str(SCRIPT), "docs-inventory", "--guide", str(guide),
                           *extra],
                          capture_output=True, text=True, timeout=120)


class DocsInventory(unittest.TestCase):
    def planted(self, old, new):
        text = GUIDE.read_text(encoding="utf-8")
        self.assertIn(old, text)
        tmp = Path(tempfile.mkdtemp())
        copy = tmp / "operator.md"
        copy.write_text(text.replace(old, new, 1), encoding="utf-8")
        return inventory(copy)

    def test_the_real_guide_passes(self):
        done = inventory(GUIDE)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("ok      docs-inventory", done.stdout)

    def test_an_untagged_fence_is_red(self):
        done = self.planted("```text\nHTTP/1.1 503", "```\nHTTP/1.1 503")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("witness=unclassified-block", done.stdout)

    def test_a_new_prose_fence_is_red(self):
        done = self.planted("```text\nHTTP/1.1 503", "```json\nHTTP/1.1 503")
        self.assertEqual(done.returncode, 0, done.stdout)  # retag within prose keeps the count
        done = self.planted("## 5. Metrics", "```text\nplanted\n```\n\n## 5. Metrics")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("witness=docs-count-mismatch", done.stdout)

    def test_a_retagged_transcript_is_red(self):
        done = self.planted("```console\n$ mkdir -m 700 trial-ca", "```text\n$ mkdir -m 700 trial-ca")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("witness=docs-count-mismatch", done.stdout)

    def test_a_deleted_exit_code_row_is_red(self):
        # The exit-7 row of runtime.md's client exit-code table removed: the
        # source still produces 7, so the table no longer covers it.
        text = RUNTIME.read_text(encoding="utf-8")
        lines = text.split("\n")
        rows = [i for i, line in enumerate(lines) if line.startswith("| 7 |")]
        self.assertEqual(len(rows), 1, "runtime.md should hold exactly one exit-7 row")
        del lines[rows[0]]
        tmp = Path(tempfile.mkdtemp())
        runtime = tmp / "runtime.md"
        runtime.write_text("\n".join(lines), encoding="utf-8")
        done = inventory(GUIDE, "--runtime-doc", str(runtime))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("witness=exit-code-table-mismatch", done.stdout)


if __name__ == "__main__":
    unittest.main()
