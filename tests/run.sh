#!/bin/bash
# tests/run.sh - run the tests with the standard library's unittest. Needs python3 and bash; nothing is installed.
#   bash tests/run.sh           every tests/test_*.py        bash tests/run.sh config      just tests/test_config.py
# Checks that ask Tailscale use the fake in tests/fixtures/tailscale. Nothing outside temporary folders is touched.
set -e
R=$(cd "$(dirname "$0")/.." && pwd); cd "$R"
if [ -n "$1" ]; then python3 -m unittest -v "tests.test_$1"; else python3 -m unittest discover -v -s tests -t .; fi
