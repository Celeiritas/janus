# Janus – notes for Claude Code

Janus is the door: he checks every Hermes delivery before it lands and draws which doors of the tailnet are open. **He never carries, moves, unpacks or runs anything.** `docs/design.md` is the spec; read the section an issue names before changing anything. The Hermes side of the contract is [hermes](https://github.com/Celeiritas/hermes) `docs/janus-contract.md`.

## Map
- `janus/` – the package, Python 3 standard library only (it may call `tailscale`). `cli.py` is the command line (`check`, `verify-approval`, `map`, `check-config`, `seen`); each issue adds its part. `config.py` reads and validates `routes.json` and `doors.json` (placeholders from `~/.config/leafy/realm.json` with argus-ui's public defaults). `check.py` runs the four checks (route, kind, shape, integrity) and **always runs all of them**, so a verdict lists every reason. `kinds.py` holds the sniffers (magic bytes / parse) and the executable refusal, which lives in code and can never be allowed by config. `shapes.py` holds the shape rules; `archives.py` lists zip/tar members without extracting; `identity.py` wraps `tailscale whois`; `approvals.py` is `verify-approval` (its contract is the last section of `docs/contract.md`); `mapper.py` is `janus map` (status + probes + `map.json` + the alert file); `seen.py` is the SQLite hash store; `log.py` the monthly JSONL logs.
- `scripts/build.sh` → `dist/janus`, a zipapp with a `python3` shebang, installed as `~/.local/bin/janus`. `scripts/check-private.sh` and `scripts/install-hooks.sh` are copied unchanged from argus-ui.
- `plugin/` – the Elaia `server` plugin `map` (pill "Janus · Map"). `units/` – `janus-map.service` (one-shot) and `.timer`, plus argus-ui's limits drop-in. `examples/` – `routes.example.json`, `doors.example.json`, placeholders only.
- `tests/` – stdlib `unittest`, `bash tests/run.sh`. `tests/fixtures/tailscale` fakes `status --json`, `whois --json` and `ping` from fixture files (`$JANUS_TAILSCALE` points Janus at it). Fixtures include one file of every kind, a zip bomb, a tar with `..`, and an executable disguised as a `.png`.

## Test before you say it works
`bash tests/run.sh` (python3, bash). `bash scripts/build.sh && ./dist/janus --version` must work on a clean Linux checkout. Add a test for every check and every reason text.

## Rules
- **Janus reads, never writes into an arrival.** Only his own log, `seen.db`, `map.json` and the alert file. Exit codes are the contract: 0 pass · 10 quarantine · 11 duplicate · 2 Janus failed (Hermes holds).
- **Executables are refused in code.** No config entry can allow `.exe`, `.ps1`, `.sh`, `.py`, `.bat`, `.jar`, `.appimage` … or PE/ELF/Mach-O/`#!` content; `check-config` fails a kind that lists one.
- **Nothing is unpacked.** Archives are checked by listing only; `.7z`/`.rar` pass with the note "contents unchecked".
- **Reasons are plain sentences** that say what happened and what to do; the Delivery page shows them as-is.
- **The Map page is a list first.** The maze is a `<figure>` drawn from the same data. Keyboard path through the list, no sideways scroll at 375 px, reduced motion = icon and word swap, state always icon + word (never colour alone). Tests cover all four.
- **Placeholders, never real names.** Public text says `{{SERVER}}`, `{{PC}}`, `{{PHONE}}`, `{{SSH}}`, `{{HOME_PC}}`, `{{HOME_SERVER}}`. Run `bash scripts/check-private.sh` before every push (`bash scripts/install-hooks.sh` once per clone). Your own notes go in `CLAUDE.local.md` (gitignored).
- **Branches are `<area>/<topic>`** (`check/kinds`, `map/page`). One issue → one pull request. The owner merges.
- **Bump `VERSION` and add a `CHANGELOG.md` entry** for every change that ships. Before 1.0 the minor number is the milestone (v0.1 = the check, v0.2 = the approver, v0.3 = the map), so work inside a milestone bumps the patch and the first change of the next milestone bumps the minor.
- Never commit `seen.db`, logs, `map.json` (it holds tailnet addresses), quarantine contents, or the owner's icons.
