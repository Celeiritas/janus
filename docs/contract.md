# The contract: Hermes ↔ Janus

Janus's side of what [hermes](https://github.com/Celeiritas/hermes) `docs/janus-contract.md` promises. Hermes calls `janus check --json <arrival>`, reads one JSON verdict from stdout and acts on the exit code. Janus reads the arrival and **never writes inside it**; it writes only its own log and `seen.db` (design §5). The Zeus ↔ Janus side (`verify-approval`) is the last section of this file.

## The call and the answer
```
janus check --json <stage>/in/<id>
```
| Exit | `verdict` | Meaning |
|---|---|---|
| 0 | `pass` | Hermes delivers |
| 10 | `quarantine` | every reason is listed; Hermes sets the arrival aside with `verdict.json` |
| 11 | `duplicate` | the same hash already passed on this route; Hermes skips it |
| 2 | — | Janus failed (bad config, `tailscale whois` unavailable, `seen.db` unusable, an unreadable arrival); Hermes holds the arrival and tries again |

```json
{ "verdict": "quarantine", "janus": "0.1.6", "sha256": "…", "kind": "image",
  "checks": { "route": "ok", "kind": "fail", "shape": "ok", "integrity": "ok" },
  "reasons": ["photo.png isn't a PNG inside."], "notes": [], "ms": 212 }
```
- All four checks always run, so `reasons` lists everything at once. Reasons are plain sentences that name the file; the Delivery page shows them as they are.
- `sha256` is what Janus hashed (for a tree, the manifest's hash). `kind` is the kind Janus matched (`tree` for a folder). `notes` are non-fatal remarks shown with ⚠: "archive contents unchecked (.7z)", "nested archives: 3 (not opened)", "tree: 3 files (image and document)".
- On exit 2 stdout carries `{"verdict": "fail", "reasons": ["Janus failed: …"], …}` and stderr says why; Hermes treats anything but 0/10/11 as "no verdict".

## A file arrival
`<arrival>/data` (the file) and `<arrival>/meta.json` as `hermes receive` writes it (Hermes `docs/files.md`): `route`, `direction` (`in`/`out`), `name`, `bytes`, `sha256`, `sender` with `via` (`ssh`, `taildrop`, `elaia`, `fetch`, `local`), `key`, `node`, `user`, `ip`, and `fetch` for fetch jobs. Janus uses `sender.key` and `sender.ip` (proved by its own `tailscale whois`); `sender.node` is never trusted.

## A tree arrival (design §3a; Hermes side: hermes#23)
A folder sent parted out, never zipped. `<arrival>/data/` is the folder's content and `<arrival>/manifest.json` lists every file:
```json
{ "version": 1, "files": [
  { "path": "a.png",      "bytes": 18234, "sha256": "…" },
  { "path": "docs/b.pdf", "bytes": 90112, "sha256": "…" } ] }
```
- `path` is relative, with forward slashes, and no component may be empty, `.`, `..` or start with a dot; no backslashes, no drive letters. Anything else is refused with the path named.
- `meta.json` is as for a file, with `"tree": true`, `name` = the folder's name, `bytes` = the sum of the files' sizes, and `sha256` = **the SHA-256 of `manifest.json`'s bytes** (what Hermes's `done <bundle> <manifest-sha256>` carries). The duplicate rule uses this hash, not each file's.
- Janus runs check 1 once, checks 2–4 on every listed file (hash and size against the manifest entry; the route's kinds for every file; archives inside the tree are listed, never opened), refuses a symlink anywhere under `data/`, a file in the folder but not in the manifest, and a file in the manifest but not in the folder (holes). At most 50 000 files.
- One verdict. Any failure quarantines the whole folder with the file named: "`setup.exe` inside `photos/` is never allowed …" (a file at the root is "inside `<folder>/`").

# The contract: Zeus ↔ Janus (`janus verify-approval`, design §4)
Zeus writes **one JSON object** (4 KB at most) to stdin and reads one back:
```
{ "action": "deploy", "repo": "you/argus-ui", "sha": "<40 hex>", "user": "<tailnet login>" | null,
  "ip": "<client address>", "when": "<ISO 8601 with offset>", "via": "elaia" | "ssh" }
```
- `action`: `deploy` or `rollback` (with `repo` as `owner/name` and a full 40-hex `sha`), or `release` (with `arrival`, a Hermes arrival id `YYYYMMDD-HHMMSS-<hex>`, instead of `repo`/`sha`).
- `via` `elaia` (the default): the Throne page is asking; `user` is the `Tailscale-User-Login` it saw and `ip` the `X-Forwarded-For` address. `via` `ssh`: `ip` is the client address from `SSH_CONNECTION` and **`user` is `null`** — Janus takes the login from the tailnet and returns it.
- `when`: the moment of the owner's yes (the 3-second hold, or the typed yes).

Janus checks, and lists **every** reason at once: the request is well formed; `routes.json` has `approvers.zeus`; `when` is within `max_age_s` (120 s by default) and not in the future; a named `user` is in `approvers.zeus.users`; `tailscale whois <ip>` names a device in `approvers.zeus.nodes`; that device has a login (a tagged device cannot approve); the login equals the named `user`, or, over ssh, is itself in `users`.

The answer, always one JSON object on stdout:
```
{ "janus": "0.2.0", "action": "deploy", "verdict": "allowed", "reasons": [], "user": "<login the tailnet reported>", "node": "<device>" }
```
| Exit | `verdict` | Meaning |
|---|---|---|
| 0 | `allowed` | Zeus logs the approval (with `user` and `node` from this answer) and starts the deploy |
| 10 | `refused` | `reasons` are plain sentences the Throne shows as-is; Zeus leaves the request pending |
| 2 | `failed` | tailscale not answering, no such peer, routes.json unreadable or with errors; Zeus holds the request and Argus glares |

Janus answers only "is this person on this device allowed, now". Whether the request is still pending, unexpired and for the right commit, the signature and the deploy are Zeus's (zeus `docs/contract.md` §5). One line goes to `~/.local/share/janus/log/approvals-YYYY-MM.jsonl` for every call: `t, action, verdict, reasons, user, node, claimed_user, repo | arrival, sha, ip, via, when, janus`. `--routes <file>` judges by another file (the config repo's deploy checks a new file before installing it).
