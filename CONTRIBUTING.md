# Contributing

## Ground rules

- Keep runtime dependencies at zero.
- Preserve Python 3.9 compatibility.
- Every security behavior change needs deterministic tests in both success and failure directions.
- Do not add real credentials, personal data or complete vendor token fixtures. Use synthetic values.
- Do not introduce Unicode em dashes or en dashes in repository text.
- Do not commit local machine paths.

## Verification

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
python3 -m build
python3 scripts/check_dist.py dist
```

Security defaults fail closed. Ergonomic escape hatches must be explicit and must produce policy-audit warnings where appropriate.
