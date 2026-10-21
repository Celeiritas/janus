"""Janus is the door of an Elaia/Argus home setup: he checks every Hermes delivery before it lands and draws which doors
of the tailnet are open. He never carries, moves, unpacks or runs anything. Python 3 standard library only.
See docs/design.md."""
from importlib import resources
from pathlib import Path


def version():
    """The version string: janus/VERSION inside the built zipapp (scripts/build.sh puts it there), else the repo's VERSION."""
    try:
        return resources.files(__name__).joinpath("VERSION").read_text().strip()
    except (FileNotFoundError, OSError):
        return (Path(__file__).resolve().parent.parent / "VERSION").read_text().strip()
