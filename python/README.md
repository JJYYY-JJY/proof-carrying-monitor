# PCM Diff Analyzer

Policy diff analyzer for the Proof-Carrying Monitor project.

Uses Z3/SMT solving to find semantic differences between two PCM policies.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

```python
from pcm_diff_analyzer.models import Policy
from pcm_diff_analyzer.analyzer import DiffAnalyzer

policy_old = Policy(rules=[])
policy_new = Policy(rules=[])
analyzer = DiffAnalyzer(policy_old, policy_new)
report = analyzer.analyze()
print(report.summary)
```

## Development

```bash
pytest --tb=short
ruff check .
mypy src/
```
