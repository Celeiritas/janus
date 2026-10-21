"""python3 -m janus ... (the zipapp built by scripts/build.sh has the same entry point at its root)."""
import sys

from janus.cli import main

sys.exit(main())
