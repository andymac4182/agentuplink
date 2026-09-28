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


def inventory(guide):
    return subprocess.run([sys.executable, str(SCRIPT), "docs-inventory", "--guide", str(guide)],
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


if __name__ == "__main__":
    unittest.main()
