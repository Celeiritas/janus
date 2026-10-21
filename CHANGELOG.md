# Changelog

## 0.1.2 – 2026-10-21
- Kind check (#4): `kinds.py` refuses executables in code (the extension list, double extensions, hidden names, and PE/ELF/Mach-O/`#!` contents, whatever the name says); sniffers for `json`, `bencode`, `text`, `image`, `audio`, `video`, `document` (PDF magic, docx/odt/epub by their zip members, text) and `archive`; the ending and the content must agree ("photo.png isn't a PNG inside."); the route must take the kind, with `taildrop_kinds` narrowing Taildrop arrivals; the kind's and the route's size caps; `kind` and the opaque-archive note in the verdict. `tests/samples.py` makes one sample of every kind in code

## 0.1.1 – 2026-10-21
- Route check (#3): `janus check` reads an arrival and runs check 1. `identity.py` asks `tailscale whois --json` for the recorded address (cached per run; a failed whois is exit 2, never a pass); an ssh sender's key and the whois node must name the same device and the self-declared `node` in `meta.json` is never trusted; `taildrop`, `elaia` (login in `users`), `fetch` (job name) and `local` senders resolve by class; the direction must fit the sender; the sender must be in the route's `from`. Every reason is listed at once. Until checks 2–4 exist a clean route check is exit 2 (the arrival waits); a refused one is already a quarantine

## 0.1.0 – 2026-10-21
- Repo skeleton (#2): the `janus` package with `--version`, `check-config` and stubs for `check`, `verify-approval`, `map` and `seen` (exit 2, so Hermes holds); `config.py` loads and validates `routes.json` and `doors.json` with placeholders from `realm.json`, warns about Hermes routes Janus doesn't know, and fails a kind that lists an executable extension; `scripts/build.sh` (zipapp) and `scripts/install.sh`; `tests/run.sh`, the fake `tailscale` with its tailnet fixtures; `examples/routes.example.json` and `doors.example.json`; CI runs the tests and the privacy check on every pull request

## 0.0.1 – 2026-10-20
- Repo created: README, CLAUDE.md, licence, privacy check (`scripts/check-private.sh`, `scripts/install-hooks.sh`, copied from argus-ui)
