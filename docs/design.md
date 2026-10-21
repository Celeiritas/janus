# Janus – design: the door check and the access map
Decided 2026-10-20. Janus is the door of an Elaia/Argus home setup ([argus-ui](https://github.com/Celeiritas/argus-ui)); it builds on the Hermes design ([hermes](https://github.com/Celeiritas/hermes), `docs/design.md` §3 "The door" and "The Janus contract"). The owner's real rules live in a private config repo; this repo holds code, contracts and examples with placeholders only.

Placeholders follow argus-ui's rule: `{{SERVER}}` (the always-on box that runs Elaia, Janus and Hermes's door), `{{PC}}` (a Windows desktop), `{{PHONE}}`, `{{SSH}}` (the ssh alias for the server), `{{HOME_PC}}`, `{{HOME_SERVER}}`; `{{LAPTOP}}` and `{{TABLET}}` stand for further devices in examples here. They are filled in on the server from `~/.config/leafy/realm.json`.

## 0. Decisions
| Question | Choice | Why |
|---|---|---|
| How Hermes calls the check | **One-shot CLI** `janus check --json <arrival dir>`, not a library and not a service | A library would run inside Hermes's process with Hermes's rights, undoing the two-file separation. A service is an always-on process. A subprocess costs about 50 ms and lets Janus run as its own user later |
| Config | **Separate** `~/.config/janus/routes.json` (who may send what) and `~/.config/janus/doors.json` (what should be open). Hermes's `routes.json` stays Hermes's | The carrier can't widen its own permissions (charter §1) |
| Large files | **Re-hash always.** Janus never trusts Hermes's streaming hash | The only check that costs time (a 10 GB disc image ≈ 30 s); Hermes's timeout already grows with size |
| Kind detection | **Extension and content** (magic bytes / parse), both must agree | Extension alone is what every mail filter learned not to trust |
| Taildrop senders | A sender class `taildrop` with a **narrower kind list** per route: torrents, magnets, images, documents | Tailscale doesn't say which of the owner's devices sent a Taildrop |
| Zeus approvals | `janus verify-approval`: tailnet user and device from `tailscale whois` on the client address, request fresh (120 s). SSH from an approved device is the fallback | Janus answers only "is this person on this device allowed"; signing and expiry are Zeus's |
| Folders | Sent as a **tree arrival**, checked file by file, one verdict for the whole folder | A folder that arrives with holes is worse than one that doesn't arrive; a zip would hide its contents from the door |
| Archives | Carried whole, **checked by listing**, never unpacked. `.7z`/`.rar` can't be listed by the stdlib: allowed from keyed devices only, verdict notes `contents: unchecked` | Nothing in the realm unpacks what Hermes carries |
| Map data | `janus-map.timer` every 5 min, one-shot; one TCP connect per expected door, skipped for devices Tailscale reports offline; two misses before "closed" | Under a second of CPU per run, no disk writes unless a state changes |
| Map page | Elaia `server` plugin **`map`**, pill "Janus · Map", `<base>/map`; a real list first, the maze drawn from the same data on top | Accessibility is a requirement, not a mode (the owner, 2026-10-20) |
| Repo | `Celeiritas/janus`, public, MIT, same tree as Hermes, privacy hook from day one | Charter §4 |

## 1. What Janus is, and isn't
- **One job: the door.** Janus decides whether a delivery may land and whether an approval may count. He also draws which doors in the realm are open.
- **He never carries, moves, unpacks or runs anything.** `janus check` reads an arrival and writes only to its own log and `seen.db`. Hermes does the renaming; Zeus does the deploying.
- **Nothing of Janus runs while idle.** `check` and `verify-approval` run when called; `janus map` runs from a timer and exits.
- **Python 3 standard library only**, one zipapp at `~/.local/bin/janus`, like Hermes. Calls `tailscale` (status, whois, ping), which {{SERVER}} already has. Subcommands: `check`, `verify-approval`, `map`, `check-config`, `seen` (list/forget a hash).

## 2. `~/.config/janus/routes.json` – who may send what
The owner's copy lives in the private config repo (`janus/routes.json`) and is copied (not symlinked) into `~/.config/janus/` on deploy. The public repo ships `examples/routes.example.json` with placeholders; the loader expands `{{PLACEHOLDERS}}` from `~/.config/leafy/realm.json` like Hermes does.

```json
{
  "version": 1,
  "senders": {
    "desktop":  { "via": "ssh", "key": "desktop", "node": "desktop" },
    "laptop": { "via": "ssh", "key": "laptop", "node": "laptop" },
    "server":       { "via": "local" },
    "taildrop":     { "via": "taildrop" },
    "elaia":        { "via": "elaia", "users": ["<tailnet login>"] },
    "fetch:decks":  { "via": "fetch", "fetch": "decks" },
    "fetch:jellyfin-themes": { "via": "fetch", "fetch": "jellyfin-themes" },
    "fetch:github": { "via": "fetch", "fetch": "github" }
  },
  "kinds": {
    "mentor-lesson": { "ext": [".json"], "sniff": "json", "max_bytes": 524288,
                       "shape": ["mentor-lesson-fields", "placeholders-known"] },
    "torrent":  { "ext": [".torrent"], "sniff": "bencode", "max_bytes": 4194304 },
    "magnet":   { "ext": [".magnet"], "sniff": "text", "max_bytes": 4096, "shape": ["magnet-uri"] },
    "note":     { "ext": [".txt"], "sniff": "text", "max_bytes": 4096 },
    "image":    { "ext": [".png", ".jpg", ".jpeg", ".webp", ".gif"], "sniff": "image", "max_bytes": 52428800 },
    "audio":    { "ext": [".mp3", ".flac", ".ogg", ".m4a", ".wav"], "sniff": "audio", "max_bytes": 1073741824 },
    "video":    { "ext": [".mkv", ".mp4", ".webm"], "sniff": "video", "max_bytes": 34359738368 },
    "document": { "ext": [".pdf", ".txt", ".md", ".docx", ".odt", ".epub"], "sniff": "document", "max_bytes": 104857600 },
    "archive":  { "ext": [".zip", ".tar", ".tar.gz", ".tgz"], "sniff": "archive", "max_bytes": 8589934592,
                  "shape": ["archive-listing"] },
    "archive-opaque": { "ext": [".7z", ".rar"], "sniff": "archive", "max_bytes": 8589934592, "note": "contents unchecked" },
    "rom":      { "ext": [".iso", ".chd", ".bin", ".cue", ".m3u", ".nsp", ".xci", ".ciso", ".wbfs", ".rvz"], "max_bytes": 68719476736 },
    "deploy-request": { "ext": [".json"], "sniff": "json", "max_bytes": 4096, "shape": ["deploy-request-fields"] }
  },
  "routes": {
    "lesson":     { "from": ["desktop", "fetch:decks"], "kinds": ["mentor-lesson"], "destination": "private" },
    "torrent":    { "from": ["desktop", "taildrop", "elaia"], "kinds": ["torrent", "magnet"] },
    "torrent-*":  { "same_as": "torrent" },
    "servermail":   { "from": ["desktop", "laptop", "taildrop"],
                    "kinds": ["image", "audio", "video", "document", "archive", "archive-opaque"],
                    "taildrop_kinds": ["image", "document"] },
    "roms":       { "from": ["desktop"], "kinds": ["rom", "archive", "archive-opaque"] },
    "jellyfin-theme": { "from": ["fetch:jellyfin-themes"], "kinds": ["audio"], "max_bytes": 20971520 },
    "pcmail": { "from": ["server", "elaia"], "kinds": ["image", "document", "note"], "destination": "private" },
    "phone":      { "from": ["server", "elaia"], "kinds": ["image", "document", "note"] },
    "deploy-request": { "from": ["fetch:github"], "kinds": ["deploy-request"] }
  },
  "approvers": {
    "zeus": { "users": ["<tailnet login>"], "nodes": ["phone", "desktop"], "max_age_s": 120 }
  }
}
```

| Field | Meaning |
|---|---|
| `senders` | Named identities. `ssh` senders must match **both** the Hermes key name and the `tailscale whois` node for the recorded IP. `taildrop` is "one of the owner's devices", nothing finer. `elaia` is the send box, identified by the `Tailscale-User-Login` header. `fetch:*` are Hermes's own fetch jobs. `local` is {{SERVER}} itself (outbound sends) |
| `kinds` | Extension list, a `sniff` rule (content must match), a size cap, optional `shape` rules |
| `routes` | Allowed senders and kinds per route. `taildrop_kinds` narrows the list for Taildrop arrivals. `destination: private` turns on the placeholder rule; `public` turns on the real-name rule. `torrent-*` covers Hermes's `torrent-movies` … `torrent-games` |
| `approvers` | Who may approve what, for `verify-approval` (§4) |

`janus check-config` validates the file, warns about a route that Hermes defines but Janus doesn't (every arrival on it would be quarantined — Hermes warns too), and about a kind that lists an executable extension (refused: see below).

## 3. `janus check` – the door, check by check
Input: an arrival folder from Hermes (`meta.json` + `data`, or `data/<tree>` + `manifest.json` for a folder). Janus reads; it never writes inside the arrival. Checks run in this order and **all run** even after a failure, so the verdict lists every reason at once.

| # | Check (charter §5) | What Janus does | Reason text (example) |
|---|---|---|---|
| 1 | **Route** | Route exists in Janus's file. Sender resolved: for `ssh`, `tailscale whois --json <meta.sender.ip>` must name the node tied to `meta.sender.key`; for `taildrop`, nothing to resolve; for `elaia`, the login must be in `senders.elaia.users`; for `fetch`, the job name must match. Sender must be in the route's `from` | "{{LAPTOP}} may not send on the roms route" · "The ssh key says {{PC}} but Tailscale says {{LAPTOP}}" |
| 2 | **Kind** | Executables refused first, **in code, never config**: extensions `.exe .msi .dll .so .dylib .ps1 .bat .cmd .sh .py .pyw .jar .appimage .scr .lnk .vbs .js .wsf .reg`; first bytes `MZ`, `\x7fELF`, Mach-O, a `#!` line; double extensions ending in one of those; names starting with `.`. Then the extension must be in an allowed kind for the route (`taildrop_kinds` for Taildrop), and the content must pass that kind's `sniff` | "`.exe` files are never allowed on any route" · "photo.png isn't a PNG inside" |
| 3 | **Shape** | Size under the kind's cap and the route's cap. Then the kind's `shape` rules: `mentor-lesson-fields` (the fields Mentor's docs require exist; Mentor validates deeper on import); `placeholders-known` (private destination: every `{{NAME}}` is one of argus-ui's seven); `public-no-real-names` (public destination: the `check-private.sh` patterns plus `~/.config/leafy/denylist.txt`); `magnet-uri`; `deploy-request-fields`; `archive-listing` (§3b) | "Lesson uses {{LAPTOP}}, which isn't a known placeholder" |
| 4 | **Integrity** | SHA-256 of `data` recomputed and compared with `meta.sha256`; bytes on disk equal `meta.bytes`. Then `seen.db` (SQLite, `~/.local/share/janus/seen.db`: hash → route, id, date): the same hash on the same route is a **duplicate** (exit 11). A pass records the hash | "The file's checksum doesn't match what {{PC}} declared" |

Output on stdout, exit 0 pass · 10 quarantine · 11 duplicate · 2 Janus failed (bad config, whois unavailable, I/O error):
```json
{ "verdict": "quarantine", "janus": "0.1.0", "sha256": "…", "kind": "image",
  "checks": { "route": "ok", "kind": "fail", "shape": "ok", "integrity": "ok" },
  "reasons": ["photo.png isn't a PNG inside"], "notes": [], "ms": 212 }
```
`notes` carries non-fatal remarks the Delivery page shows with ⚠ ("archive contents unchecked (.7z)", "nested archives: 3").

### 3a. Folders (tree arrivals)
`hermes.ps1 send <route> <folder>` sends every file under one arrival id with its relative path and ends with a manifest (paths, sizes, hashes). Janus runs checks 2–4 on **every file**, check 1 once, and refuses any path that climbs (`..`, absolute, drive letters) or contains a symlink. One verdict: all pass → Hermes renames the whole folder into place; any fail → the whole arrival is quarantined with the offending file named ("`setup.exe` inside `photos/` is never allowed"). Needs two small Hermes additions (a `bundle` id on `put`, a `done` message that triggers the single rename), filed on `Celeiritas/hermes`.

### 3b. Archives (`archive-listing`)
Zip: central directory only (milliseconds). Tar/tar.gz: stream the headers (costs about as much as hashing). Rules, without extracting anything:
- no member whose name hits the executable rules, and for zip, no member whose first bytes are PE/ELF (reads each member's header only);
- no path traversal, no absolute paths, no symlinks or hardlinks (tar);
- declared uncompressed size under the route cap and under 100× the compressed size (zip-bomb rule); member count under 50 000;
- nested archives are listed, counted in `notes`, never opened.
`.7z` and `.rar` are allowed only from keyed devices on `servermail` and `roms`; the verdict passes with the note "archive contents unchecked". Alternative, if that ever bothers you: refuse them and re-pack as zip on {{PC}}.

### 3c. Outbound
Hermes runs the same `janus check` on `direction: out` arrivals before `tailscale file cp`; the sender is `server` (local) or `elaia`.

## 4. `janus verify-approval` – the second face, for Zeus
Zeus hands Janus a request on stdin: `{ "action": "deploy", "repo": "Celeiritas/argus-ui", "sha": "<40 hex>", "user": "<login>", "ip": "<client tailnet ip>", "when": "<iso>" }`. Janus checks:
1. `user` is in `approvers.zeus.users`;
2. `tailscale whois --json <ip>` returns a node in `approvers.zeus.nodes` **and** a user profile equal to `user`;
3. `when` is within `max_age_s`; `sha` is 40 hex; `repo` is well-formed (`owner/name`).
Exit 0 allowed · 10 refused (reasons listed) · 2 failed. One line to `approvals-YYYY-MM.jsonl` either way.

Behind `tailscale serve`, the client's tailnet address arrives in `X-Forwarded-For` and the login in `Tailscale-User-Login` (both set by `tailscale serve`; **the build verifies this on {{SERVER}}** before the Throne page relies on it). If it doesn't hold, the fallback is approval by `ssh {{SSH}} 'zeus approve <id>'` from an approved device, where `SSH_CONNECTION` gives the address. Request signing, expiry and the queue itself belong to Zeus's design.

## 5. What's logged
All under `~/.local/share/janus/`; JSON lines, a new file each month, Poseidon trims files older than six months (preview, then `--go`). Nothing from inside a file is ever logged.

| File | One line per | Holds |
|---|---|---|
| `log/verdicts-YYYY-MM.jsonl` | `check` | `t`, `id`, `route`, `dir`, `sender` (via, key, node, user, ip), `name`, `bytes`, `sha256`, `kind`, per-check result, `verdict`, `reasons`, `notes`, `ms` |
| `log/approvals-YYYY-MM.jsonl` | `verify-approval` | `t`, `action`, `repo`, `sha`, `user`, `node`, `ip`, `verdict`, `reasons` |
| `log/doors-YYYY-MM.jsonl` | **state change** of a door or room, not every poll | `t`, `device`, `door`, `from`, `to`, `expected` (bool), `probe` (e.g. "connect timeout 2 s") |
| `map.json` | rewritten only when something changed | the current map (§6), read by the page |
| `seen.db` | — | hash → route, id, first seen |
| `~/.local/state/argus-ui/alerts/janus.json` | while an unexpectedly closed door exists | Hermes design §5's alert format: `{ "job": "janus-map", "level": "alert", "since": "…", "message": "{{SERVER}}'s Jellyfin door closed unexpectedly", "link": "map" }` |

Hermes writes Janus's stdout into quarantine as `verdict.json` and raises its own alert for quarantines; Janus doesn't alert on verdicts, only on doors (one alert per cause, one owner).

## 6. The map
### 6a. Data: `janus map` (timer `janus-map.timer`, every 5 min, plus Probe now)
1. `tailscale status --json`: which devices exist, online or not, OS, last seen, tailnet IPs. Devices not in `doors.json` are drawn as rooms with no doors.
2. For each device Tailscale reports **online**, one TCP connect (2 s timeout) per expected door in `doors.json`; `serve` doors are probed with a GET of the health path; `taildrop` doors count as open when the device is online (a Taildrop can't be test-sent). Offline devices are skipped entirely, so nothing retries against a sleeping machine.
3. A door changes state only after **two consecutive** probes agree (one dropped packet never makes Argus glare).
4. Write `map.json` and a `doors-*.jsonl` line only when a state changed; write or clear the alert file.

Per run: one local socket read, about ten TCP connects, under a second of CPU, no disk writes when nothing changed. Limits drop-in like every job Argus watches (argus-ui's `argus-limits.conf`: CPU 25 %, 512 MB, nice 10).

### 6b. `~/.config/janus/doors.json` – what should be open
Start from `ss -tlnp` on the server: a door is a service **bound to the tailnet address or all interfaces** that another device uses. Anything bound to localhost (Elaia's own port behind `tailscale serve`, CUPS, the stub resolver, Steam's helper ports) is not a door. In the example the server's sshd listens on a non-default port on the tailnet address only, which is common; the Hermes client reads the port from the `{{SSH}}` alias.

```json
{
  "version": 1,
  "devices": {
    "server": { "expect": "always", "doors": {
      "ssh":            { "port": 2200, "agents": ["hermes"], "note": "Hermes door key" },
      "jellyfin":       { "port": 8096, "agents": ["hermes-jellyfin"], "clients": ["phone", "tv"] },
      "audiobookshelf": { "port": 13378 },
      "qbittorrent":    { "port": 8080, "agents": ["hermes", "hermes-sort"], "note": "inside the VPN container; VPN-only to the internet" },
      "elaia":          { "serve": true, "health": "/argus/api/health", "agents": ["argus", "mentor", "janus", "hermes"] },
      "sunshine":       { "port": 47990, "expect": "sometimes", "clients": ["phone", "desktop"] },
      "steam-link":     { "port": 27036, "expect": "sometimes" },
      "syncthing":      { "port": 22000, "expect": "sometimes", "note": "planned everywhere" }
    } },
    "desktop": { "expect": "when-online", "note": "a VPN takes it off the tailnet: drawn asleep, never an alarm", "doors": {
      "taildrop": { "taildrop": true, "agents": ["hermes"] },
      "apollo":   { "port": 47990, "clients": ["server"] },
      "syncthing": { "port": 22000, "expect": "sometimes" }
    } },
    "laptop":   { "expect": "sometimes", "doors": { "taildrop": { "taildrop": true, "agents": ["hermes"] } } },
    "phone": { "expect": "sometimes", "doors": { "taildrop": { "taildrop": true, "agents": ["hermes"] } },
                        "uses": ["jellyfin", "sunshine", "elaia"] },
    "tablet":      { "expect": "sometimes", "doors": {}, "note": "not on the tailnet yet" }
  }
}
```
| `expect` | Meaning |
|---|---|
| `always` | the room should be lit and every `always` door open; a closed one is **unexpected** → alert |
| `when-online` | asleep is fine; a door that fails while Tailscale says the device is online is unexpected (e.g. Apollo crashed on an awake {{PC}}) |
| `sometimes` | never an alarm; drawn open, closed or asleep as found |
A door's own `expect` overrides its room's. `agents` = who walks through it (shown on the door); `clients`/`uses` = devices that use it (drawn as the door's far side). Other household members' devices stay off the map unless they join the tailnet. The owner's copy: `janus/doors.json` in the private config repo.

**Note for Hermes:** the Windows client takes the ssh port and address from the existing `{{SSH}}` alias (Celeiritas/hermes#24).

### 6c. The page: Janus · Map (Elaia `server` plugin `map`)
Shipped in `janus/plugin/`, installed to `~/.config/argus-ui/plugins/map/`. Janus's slate blue-grey `#4A5568`; the owner's own Janus medallion (the public repo ships a neutral placeholder icon). Argus small in the corner, glaring (red eye) while `alerts/janus.json` exists.

**Structure — the list is the page; the maze is a picture of it.**
1. **Status line:** "6 doors open · 1 closed unexpectedly · {{PC}} asleep". Feeds Elaia's Home page through the plugin `status` endpoint.
2. **Rooms list** (always rendered, first in DOM order): one `<section>` per device, {{SERVER}} first, heading = device name + state as icon **and** word (✓ open · ✕ closed · 💤 asleep · ⚠ closed unexpectedly). Inside, a list of doors: service, port, agents, clients, last probe, last change. Each door is a `<button>` that opens its detail (probe text, history from `doors-*.jsonl`, the note from `doors.json`).
3. **The maze** (`<figure>` with an SVG, `aria-labelledby` the status line, `role="img"` + a long description pointing at the list): {{SERVER}} as the central room, other rooms around it, a door = a gap in the shared wall with its services written on it; open doors drawn ajar, closed ones shut with a bar, asleep rooms dimmed with a 💤. Clicking a room or door focuses the same entry in the list, so there's one source of truth and one set of behaviour.
4. **Controls:** Probe now (runs `janus-map`), Seen (clears the alert), List / Map toggle.

**Accessibility (argus-ui `CLAUDE.md` rules + WCAG 2.1 AA):**
- **Keyboard:** Tab reaches the toggle, Probe now, then each room heading; Arrow keys move between rooms (roving tabindex), Enter/Space opens a room's doors, Esc closes; every door is a real button with a visible focus ring. The SVG is not in the tab order — the list is the keyboard path.
- **375 px:** List is the **default view on narrow screens**; the maze is one tap away and scales to width (`viewBox`, rooms stacked in one column, {{SERVER}} first). No sideways scroll. Touch targets ≥ 44 px.
- **Reduced motion:** with `prefers-reduced-motion`, no door-swing or glare pulse; a state change is a swap of icon and word with an opacity cross-fade at most. Argus's glare is a static red eye.
- **Colour never alone** (SC 1.4.1): every state carries icon + word; contrast ≥ 4.5:1 on Night.
- **Screen readers:** the list is plain headings and lists; state changes announced through one `aria-live="polite"` region on the status line; the SVG is described, never read element by element.
- **Extra steps are fine** (the owner, 2026-10-20): the toggle and the list-first default are the price of the maze being optional, not required.

**API:** `GET api/map` and `GET api/map/status` read `map.json` and the log directly (no subprocess on reads). POSTs pass Elaia's checks (same-origin, JSON, 4 KB): `probe` starts `janus-map`; `seen` clears the alert.

## 7. Resource use on {{SERVER}}
| When | What runs | Cost |
|---|---|---|
| Idle | nothing | 0 |
| A delivery | `janus check`: ms for small files; hashing time for large ones (≈ 3 s/GB) | ~15 MB, seconds |
| An approval | `janus verify-approval` + one `tailscale whois` | ms |
| Every 5 min | `janus map` | < 1 s CPU, ~10 TCP connects, no writes unless a state changed |
| Disk | `seen.db` ~100 B per delivery; logs ~250 B per verdict, a line per door *change* | — |

## 8. Public vs private
**`Celeiritas/janus` (public, MIT):**
```
janus/        check, kinds (sniffers), shapes, archives, identity (whois), approvals, map (status + probes), config, log, seen
plugin/       Elaia server plugin "map": plugin.json, plugin.py, page script + SVG renderer
units/        janus-map.service/.timer, argus-limits drop-in
examples/     routes.example.json, doors.example.json (placeholders only)
docs/         design.md (this doc, placeholders), contract.md (Hermes ↔ Janus, Zeus ↔ Janus), kinds.md, map.md
scripts/      build.sh (zipapp), install.sh, deploy.sh, check-private.sh, install-hooks.sh
tests/        run.sh (unittest): fixtures for every kind, a fake tailscale, archive and zip-bomb cases
CLAUDE.md, README.md, VERSION, CHANGELOG.md, LICENSE
```
**Private config repo:** `janus/routes.json`, `janus/doors.json`. Copied into `~/.config/janus/` on deploy, never symlinked.
**Never in any repo:** `seen.db`, logs, `map.json` (it holds tailnet addresses), quarantine contents.

## 9. Build order
| Version | Issues (one branch, one PR each; "done means" in each) | Needs |
|---|---|---|
| 0.1 "the check" | #2 skeleton, config loader, `check-config`, zipapp build · #3 route + sender identity (whois, key↔node) · #4 kinds: sniffers, executable refusal, size · #5 shapes: lesson fields, placeholders, public patterns, magnet · #6 integrity + `seen.db` + duplicates · #7 archives by listing, zip-bomb rule · #8 tree arrivals · #9 end-to-end on the server with a real Hermes arrival | Hermes 0.1 (done); Hermes tree-arrival issues for #8 |
| 0.2 "the approver" | #10 `verify-approval`, header check on the server | Zeus chat's request format |
| 0.3 "the map" | #11 `janus map` + `doors.json` + timer · #12 Map plugin page (list, maze, a11y tests: keyboard path, 375 px, reduced motion) · #13 alert file + Argus glare | argus-ui `server` plugin kind; argus-ui alert files (#8 there) |
| 1.0 | #14 install/deploy on the server; Hermes's `held/` starts flowing | all above |

Tests use a fake `tailscale` (a script on PATH that answers `status --json` and `whois --json` from fixtures), so the suite runs in the cloud.

## 10. Open for the next chats
- **Zeus:** the request record and signing; whether approvals also cover private-config deploys and `hermes release`.
- **Hermes:** tree arrivals (hermes#23), the ssh port in the Windows client (hermes#24), `notes` and `kind` in `verdict.json` (hermes#25).
- **Argus-ui:** alert files (#8), plugin `status` endpoint for Home.
- **Later:** Syncthing doors; a sender key for a laptop.

## References
- Nielsen, J. (1994). Enhancing the explanatory power of usability heuristics. *CHI '94*, 152–158. (Visibility of status; recognize, diagnose, recover.)
- W3C (2018). *WCAG 2.1*: SC 1.4.1 Use of Color, 2.1.1 Keyboard, 2.3.3 Animation from Interactions, 2.5.5 Target Size.
- Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in computer systems. *Proc. IEEE, 63*(9). (Separation of privilege; complete mediation: every arrival through one door.)
