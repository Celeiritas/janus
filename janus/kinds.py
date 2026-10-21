"""Kinds of files (docs/design.md §3 check 2). The executable refusal lives here, in code: no entry in routes.json can
allow one of these names, and `janus check-config` fails a kind that lists one. The content sniffers come with issue #4."""

# Names Janus refuses on every route. A double extension that ends in one of these (report.pdf.exe) is refused too, and
# so is a name that starts with a dot (a hidden file is never something the owner meant to send).
EXECUTABLE_EXT = (".exe", ".msi", ".dll", ".so", ".dylib", ".ps1", ".bat", ".cmd", ".sh", ".py", ".pyw", ".jar",
                  ".appimage", ".scr", ".lnk", ".vbs", ".js", ".wsf", ".reg")


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
    base = str(name).rsplit("/", 1)[-1]
    if base.startswith("."):
        return "%s is a hidden file (its name starts with a dot), which is never allowed on any route." % name
    return None
