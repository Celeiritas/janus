"""Kinds of files (docs/design.md §3 check 2, §0 "kind detection"). Extension and content must agree: a kind's `sniff`
rule reads the file's magic bytes or parses it. The executable refusal lives here, in code: no entry in routes.json can
allow one of these names or one of these contents, and `janus check-config` fails a kind that lists one."""
import json
import struct
import zipfile

# Names Janus refuses on every route. A double extension that ends in one of these (report.pdf.exe) is refused too, and
# so is a name that starts with a dot (a hidden file is never something the owner meant to send).
EXECUTABLE_EXT = (".exe", ".msi", ".dll", ".so", ".dylib", ".ps1", ".bat", ".cmd", ".sh", ".py", ".pyw", ".jar",
                  ".appimage", ".scr", ".lnk", ".vbs", ".js", ".wsf", ".reg")
# Contents Janus refuses on every route, whatever the name says: Windows PE, ELF, Mach-O (thin and fat), a #! line.
MACH_O = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
          b"\xbe\xba\xfe\xca")
HEAD = 1 << 16          # how much of a file a sniffer reads: the first 64 KB (whole-file parsers read it all)
WHOLE_MAX = 1 << 26     # a parser (json, bencode, text) reads the whole file only up to 64 MB; the caps are far lower

# What a file ending should hold, for the reason sentence ("photo.png isn't a PNG inside").
LABEL = {".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG", ".webp": "WebP", ".gif": "GIF",
         ".mp3": "MP3", ".flac": "FLAC", ".ogg": "Ogg", ".m4a": "M4A", ".wav": "WAV",
         ".mkv": "Matroska", ".mp4": "MP4", ".webm": "WebM",
         ".pdf": "PDF", ".docx": "docx", ".odt": "OpenDocument", ".epub": "EPUB", ".txt": "plain text", ".md": "plain text",
         ".zip": "zip", ".tar": "tar", ".tar.gz": "gzip", ".tgz": "gzip", ".7z": "7z", ".rar": "RAR",
         ".json": "JSON", ".torrent": "torrent (bencode)", ".magnet": "plain text"}


# ---------- the executable refusal ----------

def executable_extension(name):
    """The refused extension a file name ends in (lower-case), or None. `report.pdf.exe` -> `.exe`."""
    low = str(name).lower().rstrip()
    for ext in EXECUTABLE_EXT:
        if low.endswith(ext):
            return ext
    return None


def refused_name(name):
    """Why a name alone is refused, as one plain sentence, or None when the name is fine."""
    ext = executable_extension(name)
    if ext:
        return "%s files are never allowed on any route (%s)." % (ext, name)
    base = str(name).replace("\\", "/").rsplit("/", 1)[-1]
    if base.startswith("."):
        return "%s is a hidden file (its name starts with a dot), which is never allowed on any route." % name
    return None


def executable_content(head):
    """What kind of program the first bytes announce (a Windows program, ...), or None."""
    if head[:2] == b"MZ":
        return "a Windows program (it starts with MZ)"
    if head[:4] == b"\x7fELF":
        return "a Linux program (it starts with ELF)"
    if head[:4] in MACH_O:
        return "a Mac program (a Mach-O header)"
    if head[:2] == b"#!":
        return "a script (it starts with a #! line)"
    return None


def refused_content(name, head):
    """Why the content alone is refused, as one plain sentence, or None."""
    what = executable_content(head)
    if what:
        return "%s is %s, which is never allowed on any route, whatever its name says." % (name, what)
    return None


# ---------- sniffers: does the content match the ending? ----------

def ext_of(name, exts):
    """The longest ending from `exts` that the name has (so .tar.gz wins over .gz), or None."""
    low = str(name).lower()
    best = None
    for e in exts:
        if low.endswith(e) and len(low) > len(e) and (best is None or len(e) > len(best)):
            best = e
    return best


def is_text(data, complete):
    """UTF-8 text with no NUL. `complete` is False when `data` is only the start of the file (a cut character is fine)."""
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        return not complete and e.start >= len(data) - 3 and e.reason.startswith("unexpected end")


def is_json(data):
    try:
        json.loads(data.decode("utf-8"))
        return True
    except (ValueError, UnicodeDecodeError):
        return False


def bencode_ok(data):
    """A complete, well-formed bencode value (what a .torrent is), parsed without building anything large."""
    try:
        end = _bencode(data, 0, 0)
    except (ValueError, IndexError, RecursionError):
        return False
    return end == len(data)


def _bencode(d, i, depth):
    if depth > 64:
        raise ValueError
    c = d[i:i + 1]
    if c == b"i":
        j = d.index(b"e", i)
        int(d[i + 1:j])
        return j + 1
    if c == b"l" or c == b"d":
        i += 1
        want_key = c == b"d"
        while d[i:i + 1] != b"e":
            if want_key and d[i:i + 1] not in b"0123456789":
                raise ValueError
            i = _bencode(d, i, depth + 1)
            if c == b"d":
                i = _bencode(d, i, depth + 1)
        return i + 1
    if c and c in b"0123456789":
        j = d.index(b":", i)
        n = int(d[i:j])
        if n < 0 or j + 1 + n > len(d):
            raise ValueError
        return j + 1 + n
    raise ValueError


IMAGE = {".png": lambda h: h[:8] == b"\x89PNG\r\n\x1a\n",
         ".jpg": lambda h: h[:3] == b"\xff\xd8\xff", ".jpeg": lambda h: h[:3] == b"\xff\xd8\xff",
         ".webp": lambda h: h[:4] == b"RIFF" and h[8:12] == b"WEBP",
         ".gif": lambda h: h[:6] in (b"GIF87a", b"GIF89a")}
AUDIO = {".mp3": lambda h: h[:3] == b"ID3" or (len(h) > 1 and h[0] == 0xFF and h[1] & 0xE6 == 0xE2),
         ".flac": lambda h: h[:4] == b"fLaC", ".ogg": lambda h: h[:4] == b"OggS",
         ".m4a": lambda h: h[4:8] == b"ftyp" and h[8:12] in (b"M4A ", b"M4B ", b"mp42", b"isom", b"iso2"),
         ".wav": lambda h: h[:4] == b"RIFF" and h[8:12] == b"WAVE"}
VIDEO = {".mkv": lambda h: h[:4] == b"\x1a\x45\xdf\xa3" and b"matroska" in h[:64],
         ".webm": lambda h: h[:4] == b"\x1a\x45\xdf\xa3" and b"webm" in h[:64],
         ".mp4": lambda h: h[4:8] == b"ftyp"}
ARCHIVE = {".zip": lambda h: h[:4] in (b"PK\x03\x04", b"PK\x05\x06"),
           ".tar": lambda h: h[257:262] == b"ustar",
           ".tar.gz": lambda h: h[:2] == b"\x1f\x8b", ".tgz": lambda h: h[:2] == b"\x1f\x8b",
           ".7z": lambda h: h[:6] == b"7z\xbc\xaf\x27\x1c", ".rar": lambda h: h[:7] == b"Rar!\x1a\x07\x00" or h[:7] == b"Rar!\x1a\x07\x01"}
ZIP_DOCUMENT = {".docx": lambda names, mime: "[Content_Types].xml" in names and any(n.startswith("word/") for n in names),
                ".odt": lambda names, mime: mime == b"application/vnd.oasis.opendocument.text",
                ".epub": lambda names, mime: mime == b"application/epub+zip"}


def zip_document(path, ext):
    """A docx/odt/epub is a zip with a telling member: the central directory and the tiny `mimetype` entry, nothing more."""
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            mime = b""
            if "mimetype" in names and z.getinfo("mimetype").file_size <= 256:
                mime = z.read("mimetype").strip()
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
        return False
    return ZIP_DOCUMENT[ext](names, mime)


def sniff(rule, path, name, ext, head, size):
    """Does the content pass the kind's sniff rule for this ending? Magic tables for the ending when it has one,
    else any magic of the family; parsers read the whole file."""
    def whole():
        if size > WHOLE_MAX:
            return None
        with open(path, "rb") as f:
            return f.read(WHOLE_MAX + 1)
    if rule == "json":
        data = whole()
        return data is not None and is_json(data)
    if rule == "bencode":
        data = whole()
        return data is not None and head[:1] == b"d" and bencode_ok(data)
    if rule == "text":
        data = whole()
        return data is not None and is_text(data, True)
    if rule == "image":
        return _family(IMAGE, ext, head)
    if rule == "audio":
        return _family(AUDIO, ext, head)
    if rule == "video":
        return _family(VIDEO, ext, head)
    if rule == "archive":
        return _family(ARCHIVE, ext, head)
    if rule == "document":
        if ext == ".pdf":
            return head[:5] == b"%PDF-"
        if ext in ZIP_DOCUMENT:
            return zip_document(path, ext)
        if ext in (".txt", ".md"):
            return is_text(head, size <= len(head))
        return head[:5] == b"%PDF-" or (head[:4] == b"PK\x03\x04" and any(zip_document(path, e) for e in ZIP_DOCUMENT)) \
            or is_text(head, size <= len(head))
    return True


def _family(table, ext, head):
    if ext in table:
        return bool(table[ext](head))
    return any(f(head) for f in table.values())


def label(ext, rule):
    """What the ending promises, for a sentence: PNG, plain text, JSON, ..."""
    return LABEL.get(ext) or {"json": "JSON", "bencode": "bencode", "text": "plain text"}.get(rule) or (rule or "that")


def read_head(path):
    with open(path, "rb") as f:
        return f.read(HEAD)
