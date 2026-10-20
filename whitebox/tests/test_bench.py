"""The benchmark harness must report no regressions on the in-repo fixture."""

import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for p in ("whitebox", "triager"):
    sys.path.insert(0, os.path.join(ROOT, p))

from offat_wb import cpg  # noqa: E402

BENCH = os.path.join(ROOT, "whitebox", "bench")
HAVE_TS = importlib.util.find_spec("tree_sitter_language_pack") is not None


def _load_run():
    spec = importlib.util.spec_from_file_location("offat_bench_run", os.path.join(BENCH, "run.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(cpg.AVAILABLE and HAVE_TS, "needs networkx + tree-sitter for the JS targets")
class TestBenchmark(unittest.TestCase):
    def test_fixture_is_perfect(self):
        run = _load_run()
        report = run.run(os.path.join(BENCH, "answer_key.json"), os.path.join(ROOT, "whitebox"))
        self.assertEqual(report["fn"], 0, f"missed flows: {[m for t in report['targets'] for m in t['misses']]}")
        self.assertEqual(report["fp"], 0, f"false positives: {[s for t in report['targets'] for s in t['spurious']]}")
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["precision"], 1.0)
        self.assertGreaterEqual(report["tp"], 16)


if __name__ == "__main__":
    unittest.main()
