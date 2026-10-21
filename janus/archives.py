"""Archives by listing (docs/design.md §3b): the `archive-listing` shape rule. A zip is read by its central directory
and the first bytes of each member; a tar (plain or gzip) by streaming its headers. Nothing is ever extracted, nothing
is written. Rules: no member that hits the executable rules, no path that climbs or is absolute, no symlinks or
hardlinks, declared size under the cap and under 100x the packed size, at most 50 000 members; nested archives are
counted into the notes and never opened. .7z and .rar can't be listed by the standard library: the kind's note says so."""
import re
import tarfile
import zipfile
import zlib

from janus import config, kinds

MAX_MEMBERS = 50000
BOMB_RATIO = 100
BOMB_FLOOR = 1 << 20         # the ratio rule starts at 1 MB declared: a tiny text zip is never a bomb
NESTED = (".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst")
DRIVE = re.compile(r"^[A-Za-z]:")
SYMLINK = 0o120000


class Listing:
    """What one archive declares: members, sizes, and the sentences it earned."""
    def __init__(self, name, cap):
        self.name, self.cap = name, cap
        self.members = self.unpacked = self.packed = self.nested = 0
        self.reasons, self.notes = [], []
        self._said = set()

    def say(self, sentence):
        if sentence not in self._said:
            self._said.add(sentence)
            self.reasons.append(sentence)

    def member(self, path, size, is_dir, link, head):
        """One member's name, size and first bytes, judged."""
        self.members += 1
        self.unpacked += max(size, 0)
        clean = path.replace("\\", "/")
        parts = [p for p in clean.split("/") if p not in ("", ".")]
        if clean.startswith("/") or DRIVE.match(clean) or ".." in parts:
            self.say("%s has a member whose path climbs out of the folder (%s), which is never allowed." % (self.name, path))
        if link:
            self.say("%s has a %s (%s), which is never allowed inside an archive." % (self.name, link, path))
        if is_dir:
            return
        base = parts[-1] if parts else path
        ext = kinds.executable_extension(base)
        if ext:
            self.say("%s inside %s is never allowed on any route (%s files never are)." % (base, self.name, ext))
        elif base.startswith("."):
            self.say("%s inside %s is a hidden file (its name starts with a dot), which is never allowed." % (base, self.name))
        elif head:
            what = kinds.executable_content(head)
            if what:
                self.say("%s inside %s is %s, which is never allowed on any route." % (base, self.name, what))
        if kinds.ext_of(base, NESTED):
            self.nested += 1

    def finish(self):
        if self.members > MAX_MEMBERS:
            self.say("%s holds more than %s members, more than Janus will list; split it." % (self.name, format(MAX_MEMBERS, ",").replace(",", " ")))
        if self.cap and self.unpacked > self.cap:
            self.say("%s would unpack to %s, over the %s cap." % (self.name, config.size(self.unpacked), config.size(self.cap)))
        if self.unpacked >= BOMB_FLOOR and self.unpacked > BOMB_RATIO * max(self.packed, 1):
            self.say("%s says it holds %s packed into %s (%d times smaller), which is what a zip bomb looks like."
                     % (self.name, config.size(self.unpacked), config.size(self.packed), self.unpacked // max(self.packed, 1)))
        if self.nested:
            self.notes.append("nested archives: %d (not opened)" % self.nested)
        return self.reasons, self.notes


def listing(name, path, cap, ext):
    """(reasons, notes) for an archive, without extracting anything. `cap` is the route's (or kind's) size cap."""
    L = Listing(name, cap)
    if ext == ".zip":
        _zip(L, path)
    elif ext in (".tar", ".tar.gz", ".tgz"):
        _tar(L, path)
    else:
        L.notes.append("archive contents unchecked (%s)" % ext)
        return L.reasons, L.notes
    return L.finish()


def _zip(L, path):
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            L.packed = sum(i.compress_size for i in infos)
            for i in infos:
                if L.members >= MAX_MEMBERS:
                    L.members = MAX_MEMBERS + 1
                    break
                link = "symbolic link" if (i.external_attr >> 16) & 0o170000 == SYMLINK else None
                head = b""
                if not i.is_dir() and not link and i.file_size:
                    if i.flag_bits & 0x1:
                        L.say("%s has an encrypted member (%s), which can't be checked." % (L.name, i.filename))
                    else:
                        try:
                            with z.open(i) as f:
                                head = f.read(4)
                        except (RuntimeError, NotImplementedError, zipfile.BadZipFile, EOFError, zlib.error, OSError) as e:
                            L.say("%s has a member that can't be read (%s: %s)." % (L.name, i.filename, str(e)[:80]))
                L.member(i.filename, i.file_size, i.is_dir(), link, head)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, RuntimeError) as e:
        L.say("%s's table of contents can't be read (%s), so its members can't be checked." % (L.name, str(e)[:80]))


def _tar(L, path):
    try:
        L.packed = path.stat().st_size
        with tarfile.open(str(path), mode="r|*") as t:
            for m in t:
                if L.members >= MAX_MEMBERS:
                    L.members = MAX_MEMBERS + 1
                    break
                link = "symbolic link" if m.issym() else "hard link" if m.islnk() else None
                head = b""
                if m.isreg() and m.size:
                    f = t.extractfile(m)
                    if f is not None:
                        head = f.read(4)
                L.member(m.name, m.size if m.isreg() else 0, m.isdir(), link, head)
    except (tarfile.TarError, OSError, EOFError, ValueError, zlib.error) as e:
        L.say("%s's headers can't be read (%s), so its members can't be checked." % (L.name, str(e)[:80]))
