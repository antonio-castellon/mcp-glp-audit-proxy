# Contributing

The proxy is small on purpose. It mediates a tool call, writes one audit line, and fails closed. A change that widens what an operator can do by default does not fit.

Open an issue first if the change is not clear yet. Branch from `main`. Do not commit secrets or tokens. Tests and CI must stay green. Keep the change small and safe: read-only by default, and allowlists for what may run.

`python -m pytest -q` is the local check. CI runs that suite on Python 3.11, 3.12, and 3.13.
