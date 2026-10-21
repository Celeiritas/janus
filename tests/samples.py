"""One small, well-formed sample of every kind the example routes.json knows (made in code, so no binary fixture is
committed), plus the impostors: a Windows program renamed .png, a script, a double extension. `sample(ext)` gives the
bytes for an ending."""
import gzip
import hashlib
import io
import json
import tarfile
import zipfile

LESSON = {
    "metadata": {"timestamp": "2026-10-21T12:00:00", "module_name": "weather_cache", "project": "argus-ui",
                 "source_files": ["server/sky.py"], "concepts_covered": ["context managers"]},
    "cta_summary": {"schematic_mental_model": "One cache on {{SERVER}}, one lock.", "design_rules_heuristics": "...",
                    "hard_rules_invariants": "...", "hci_human_factors_bridge": "..."},
    "tier_1_faded_code_drills": [{"id": "drill_01", "file_breadcrumb": "server -> sky.py -> current()",
                                  "context_comment": "...", "full_canonical_code": "return _mem",
                                  "level_1_fade": "return {{BLANK_1}}", "answers": {"level_1": ["_mem"]}}],
    "tier_3_terminology_cards": [{"id": "term_01", "term": "context manager", "concise_definition": "...",
                                  "cloze_prompt": "`with _lock:` uses the lock as a {{BLANK}}."}],
}
DEPLOY_REQUEST = {"type": "deploy-request", "repo": "Celeiritas/argus-ui", "sha": "a" * 40, "previous": "b" * 40,
                  "subject": "Mentor: Learn phase", "version": "4.9.0", "checks": "success",
                  "changelog": ["- Learn cards"], "seen": "2026-10-21T15:00:00-06:00"}
MAGNET = "magnet:?xt=urn:btih:" + "c" * 40 + "&dn=example\n"


def zip_bytes(members, stored_first=None):
    """A zip from {name: bytes}; `stored_first` is written first, uncompressed (what odt/epub need for `mimetype`)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        if stored_first:
            z.writestr(stored_first[0], stored_first[1], compress_type=zipfile.ZIP_STORED)
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def tar_bytes(members, gz=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    return gzip.compress(raw) if gz else raw


def torrent_bytes():
    pieces = hashlib.sha1(b"x").digest()
    return (b"d8:announce18:http://example.com4:infod6:lengthi1e4:name7:example12:piece lengthi16384e6:pieces20:"
            + pieces + b"ee")


def ebml(doctype):
    return b"\x1a\x45\xdf\xa3" + b"\xa3" + b"\x42\x82" + bytes([0x80 | len(doctype)]) + doctype + b"\x00" * 32


SAMPLES = {
    ".png": b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 32,
    ".jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 32,
    ".jpeg": b"\xff\xd8\xff\xe1\x00\x10Exif\x00" + b"\x00" * 32,
    ".webp": b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 32,
    ".gif": b"GIF89a\x01\x00\x01\x00" + b"\x00" * 32,
    ".mp3": b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\xff\xfb\x90\x00" + b"\x00" * 32,
    ".flac": b"fLaC\x00\x00\x00\x22" + b"\x00" * 32,
    ".ogg": b"OggS\x00\x02" + b"\x00" * 32,
    ".m4a": b"\x00\x00\x00\x20ftypM4A \x00\x00\x00\x00M4A mp42isom" + b"\x00" * 32,
    ".wav": b"RIFF\x24\x00\x00\x00WAVEfmt " + b"\x00" * 32,
    ".mkv": ebml(b"matroska"),
    ".webm": ebml(b"webm"),
    ".mp4": b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00isomiso2mp41" + b"\x00" * 32,
    ".pdf": b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n",
    ".txt": "A plain note.\n".encode(),
    ".md": "# Notes\n\nPlain text with an accent: café.\n".encode(),
    ".docx": zip_bytes({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>"}),
    ".odt": zip_bytes({"content.xml": b"<office:document-content/>"}, ("mimetype", b"application/vnd.oasis.opendocument.text")),
    ".epub": zip_bytes({"META-INF/container.xml": b"<container/>"}, ("mimetype", b"application/epub+zip")),
    ".zip": zip_bytes({"photos/a.txt": b"one", "photos/b.txt": b"two"}),
    ".tar": tar_bytes({"photos/a.txt": b"one", "photos/b.txt": b"two"}),
    ".tar.gz": tar_bytes({"photos/a.txt": b"one"}, gz=True),
    ".tgz": tar_bytes({"photos/a.txt": b"one"}, gz=True),
    ".7z": b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 32,
    ".rar": b"Rar!\x1a\x07\x00" + b"\x00" * 32,
    ".iso": b"\x00" * 2048 + b"\x01CD001\x01\x00" + b"\x00" * 64,
    ".chd": b"MComprHD" + b"\x00" * 32,
    ".bin": b"\x00\xff\x00\xff" + b"\x00" * 32,
    ".cue": b'FILE "game.bin" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n',
    ".m3u": b"disc1.chd\ndisc2.chd\n",
    ".nsp": b"PFS0" + b"\x00" * 32,
    ".xci": b"\x00" * 64,
    ".ciso": b"CISO" + b"\x00" * 32,
    ".wbfs": b"WBFS" + b"\x00" * 32,
    ".rvz": b"RVZ\x01" + b"\x00" * 32,
    ".json": json.dumps(LESSON).encode(),
    ".torrent": torrent_bytes(),
    ".magnet": MAGNET.encode(),
}
IMPOSTORS = {
    "exe": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 48,
    "elf": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 48,
    "macho": b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 48,
    "script": b"#!/bin/sh\necho hello\n",
    "binary-text": b"not text \x00 at all",
}


def sample(ext):
    return SAMPLES[ext]
