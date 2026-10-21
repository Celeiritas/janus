"""Tree arrivals (docs/design.md §3a, docs/contract.md): a folder sent parted out as `data/<tree>` plus a
`manifest.json` of paths, sizes and hashes. Check 1 ran once; here checks 2-4 run on every file and the folder is
judged as a whole: a path that climbs, a symlink anywhere, a file missing from the folder or from the manifest, a
manifest whose hash isn't what the sender declared. One verdict; a failing file is named in its reason."""
import hashlib
import json
import os
import re
from pathlib import Path

from janus import check as _check
from janus import config

MAX_FILES = 50000
DRIVE = re.compile(r"^[A-Za-z]:")


def clean_path(path):
    """Why a manifest path is refused, or None. Relative, forward slashes, no component that is empty, `.`, `..` or
    hidden (starts with a dot), no backslash, no drive letter."""
    if not isinstance(path, str) or not path:
        return "an empty path"
    if "\\" in path or "\x00" in path:
        return "a path with a backslash or a NUL in it (%s)" % path
    if path.startswith("/") or DRIVE.match(path):
        return "an absolute path (%s)" % path
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return "a path that climbs out of the folder (%s)" % path
    if any(p.startswith(".") for p in parts):
        return "a hidden name in a path (%s)" % path
    return None


def read_manifest(arrival):
    """The manifest's bytes and its parsed document; Failed when it can't be read (Hermes left a broken arrival)."""
    try:
        raw = arrival.manifest.read_bytes()
    except OSError as e:
        raise _check.Failed("cannot read %s (%s)" % (arrival.manifest, e.strerror or e))
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise _check.Failed("%s is not JSON (%s)" % (arrival.manifest, e))
    return raw, doc


def on_disk(root, v, tree):
    """Every regular file under data/ as a relative path with forward slashes. A symlink (file or folder) anywhere is
    refused and not followed; the folder is judged as it is."""
    found = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel = Path(dirpath).relative_to(root)
        for d in list(dirnames):
            if (Path(dirpath) / d).is_symlink():
                v.fail("shape", "%s inside %s/ is a symbolic link, which is never allowed." % ((rel / d).as_posix(), tree))
                dirnames.remove(d)
        for name in filenames:
            p = Path(dirpath) / name
            key = (rel / name).as_posix()
            if p.is_symlink():
                v.fail("shape", "%s inside %s/ is a symbolic link, which is never allowed." % (key, tree))
            elif p.is_file():
                found[key] = p
            else:
                v.fail("shape", "%s inside %s/ is not a plain file, which is never allowed." % (key, tree))
    return found


def check_tree(ctx, v):
    """Checks 2-4 on every file of the tree, the folder's own rules, and the manifest's hash. Sets v.sha256 (the
    manifest's hash, what the duplicate rule uses) and v.kind ("tree")."""
    a = ctx.arrival
    tree = a.name.rstrip("/") or "the folder"
    sender = _check.who(ctx)
    v.kind = "tree"
    raw, doc = read_manifest(a)
    v.sha256 = hashlib.sha256(raw).hexdigest()
    declared = a.meta.get("sha256")
    if not isinstance(declared, str) or declared.lower() != v.sha256:
        v.fail("integrity", "%s/'s manifest checksum doesn't match what %s declared (the folder may have arrived "
                            "incomplete or changed on the way)." % (tree, sender))
    if not a.data.is_dir() or a.data.is_symlink():
        v.fail("integrity", "%s/ has no data folder to check." % tree)
        return
    files = doc.get("files") if isinstance(doc, dict) else None
    if not isinstance(files, list):
        v.fail("integrity", "%s/'s manifest has no files list, so the folder can't be checked." % tree)
        return
    if len(files) > MAX_FILES:
        v.fail("shape", "%s/ holds %d files, more than the %s Janus will check; send it in parts."
               % (tree, len(files), format(MAX_FILES, ",").replace(",", " ")))
        return
    disk = on_disk(a.data, v, tree)
    listed = {}
    total = 0
    kinds_seen = []
    for i, entry in enumerate(files, 1):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) \
                or not isinstance(entry.get("sha256"), str) or not isinstance(entry.get("bytes"), int) \
                or isinstance(entry.get("bytes"), bool):
            v.fail("integrity", "%s/'s manifest entry %d is malformed (each needs path, bytes and sha256)." % (tree, i))
            continue
        path = entry["path"]
        why = clean_path(path)
        if why:
            v.fail("shape", "%s/'s manifest has %s, which is never allowed." % (tree, why))
            continue
        if path in listed:
            v.fail("integrity", "%s/'s manifest lists %s twice." % (tree, path))
            continue
        listed[path] = entry
        total += entry["bytes"]
    for path in sorted(set(disk) - set(listed)):
        v.fail("integrity", "%s inside %s/ is in the folder but not in the manifest." % (path, tree))
    for path in sorted(listed):
        entry = listed[path]
        if path not in disk:
            v.fail("integrity", "%s inside %s/ is in the manifest but not in the folder (the folder arrived with holes)."
                   % (path, tree))
            continue
        base = path.rsplit("/", 1)[-1]
        where = path.rsplit("/", 1)[0] + "/" if "/" in path else tree + "/"
        item = _check.Item("%s inside %s" % (base, where), disk[path], entry["sha256"], entry["bytes"], base=base)
        _check.check_file(ctx, v, item)
        if ctx.kind is not None and ctx.kind.name not in kinds_seen:
            kinds_seen.append(ctx.kind.name)
    if a.meta.get("bytes") != total:
        v.fail("integrity", "%s/'s manifest adds up to %s but %s declared %s." % (tree, config.size(total), sender,
               config.size(a.meta["bytes"]) if isinstance(a.meta.get("bytes"), int) else repr(a.meta.get("bytes"))))
    v.kind = "tree"                      # the per-file checks set the kind of the file they judged
    n = len(listed)
    v.notes.append("tree: %d file%s%s" % (n, "" if n == 1 else "s", " (%s)" % config.join(kinds_seen) if kinds_seen else ""))
