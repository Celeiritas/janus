"""Shared test scaffolding: a temporary HOME with the example config, the fake tailscale, and hand-made arrivals as
Hermes would leave them (meta.json + data). Nothing outside the temporary folder is touched."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

from janus import check, config

ROOT = Path(__file__).resolve().parent.parent
FAKE_TAILSCALE = ROOT / "tests" / "fixtures" / "tailscale"
ROUTES_EXAMPLE = ROOT / "examples" / "routes.example.json"
DOORS_EXAMPLE = ROOT / "examples" / "doors.example.json"
PC_IP, LAPTOP_IP, PHONE_IP, GUEST_IP = "192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"   # tests/fixtures/tailnet


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class Realm:
    """A temporary HOME: Janus's config (the examples, or a changed copy), the fake tailscale, a stage for arrivals."""
    def __init__(self, tmp):
        self.home = Path(tmp) / "home"
        self.routes = self.home / ".config" / "janus" / "routes.json"
        self.doors = self.home / ".config" / "janus" / "doors.json"
        self.stage = self.home / "stage"
        self.routes.parent.mkdir(parents=True)
        self.stage.mkdir(parents=True)
        self.env = mock.patch.dict(os.environ, {"HOME": str(self.home), "JANUS_CONFIG": str(self.routes),
                                                "JANUS_DOORS": str(self.doors), "JANUS_TAILSCALE": str(FAKE_TAILSCALE),
                                                "HERMES_CONFIG": str(self.home / "no-hermes.json"),
                                                "LEAFY_REALM": str(self.home / "no-realm.json"),
                                                "LEAFY_DENYLIST": str(self.home / "no-denylist.txt")})
        self.env.start()
        self.routes_doc = json.loads(ROUTES_EXAMPLE.read_text())
        self.write()
        self.n = 0

    def stop(self):
        self.env.stop()

    def write(self, routes=None):
        self.routes.write_text(json.dumps(routes or self.routes_doc))
        self.doors.write_text(DOORS_EXAMPLE.read_text())
        return self

    def config(self):
        return config.load()

    def arrival(self, name, data=b"hello\n", route="servermail", via="ssh", key="desktop", ip=PC_IP, node=None,
                user=None, fetch=None, direction="in", digest=None, size=None, subpath=None, **more):
        """One arrival folder as Hermes leaves it in <stage>/in/<id>/: data (the bytes) and meta.json."""
        self.n += 1
        folder = self.stage / "in" / ("20261021-120000-%06x" % self.n)
        folder.mkdir(parents=True)
        (folder / "data").write_bytes(data)
        sender = {"via": via, "key": key if via == "ssh" else None, "node": node, "user": user, "ip": ip if via == "ssh" else None}
        if via == "fetch":
            sender["fetch"] = fetch
        meta = {"id": folder.name, "route": route, "direction": direction, "name": name,
                "bytes": len(data) if size is None else size, "sha256": digest or sha256(data),
                "sender": sender, "received": "2026-10-21T12:00:00-06:00", "hermes": "0.1.4"}
        if subpath:
            meta["subpath"] = subpath
        meta.update(more)
        (folder / "meta.json").write_text(json.dumps(meta))
        return folder

    def check(self, folder, **env):
        """check.run on an arrival: (exit code, verdict dict); a Failed comes back as (2, {"failed": message})."""
        try:
            return check.run(folder, env={**os.environ, **env})
        except check.Failed as e:
            return 2, {"failed": str(e)}

    def cli(self, *args, input=None, **env):
        """Run `janus <args>` as a subprocess; `input` is fed to stdin (verify-approval reads its request there)."""
        return subprocess.run([sys.executable, "-m", "janus", *args], cwd=ROOT, capture_output=True, text=True,
                              input=input if input is not None else "", env={**os.environ, **env}, timeout=60)


def snapshot(folder):
    """Every path under a folder with its size and mtime: to prove Janus wrote nothing inside an arrival."""
    out = {}
    for p in sorted(Path(folder).rglob("*")):
        st = p.lstat()
        out[str(p)] = (st.st_size, st.st_mtime_ns)
    return out
