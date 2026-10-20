# Code-graph benchmark

Scores the taint engine against a labeled answer key: precision, recall
(true-positive rate) and F1, overall and per vulnerability class.

```bash
python whitebox/bench/run.py                                   # score + report
python whitebox/bench/run.py --fail-under-recall 1.0 \
                            --fail-under-precision 1.0          # CI gate
python whitebox/bench/run.py --markdown bench.md --json bench.json
```

`answer_key.json` lists, per target, the `(file, class)` flows the engine must
prove (`expect`) and the routes that must stay silent (`silent`, the safe
twins). Matching is by `(file, class)` so small edits to a fixture do not churn
the key. A finding on a silent route, or one not in `expect`, counts as a false
positive; a missing `expect` entry is a false negative.

CI runs the in-repo `taint_app` fixture and gates at 100% precision and recall,
so a regression that drops a true positive or introduces a false positive fails
the build. Tree-sitter-only targets are skipped when tree-sitter is absent.

## Scoring external apps

Point the harness at your own answer key and targets:

```bash
python whitebox/bench/run.py --key my_key.json --root /path/to/apps
```

A target whose `path` is missing is skipped, so an answer key may reference
apps that are cloned only locally (e.g. OWASP Juice Shop) without breaking CI.
