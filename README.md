# Janus

Janus is the door of an Elaia/Argus home setup ([argus-ui](https://github.com/Celeiritas/argus-ui)). He has two faces:

1. **The check.** Every delivery [Hermes](https://github.com/Celeiritas/hermes) brings is verified before it lands: the sender is who Tailscale says it is (`tailscale whois`, never a self-declared name), the route allows that sender and that kind of file, the file *is* what its name says (content, not just extension), it is under the size cap, its SHA-256 matches, it is not a duplicate, and it is **never** an executable or a script on any route. Pass → Hermes delivers. Fail → quarantine, with a reason in plain words that the Delivery page shows. Janus also answers Zeus's question "is this approval from an allowed person on an allowed device?"
2. **The map.** An Elaia page that draws the tailnet as rooms (devices) and doors (services) — open, closed, or asleep — from `tailscale status --json` plus small reachability probes run on the server. Argus glares at a door that closed unexpectedly.

**Janus carries nothing and runs nothing.** `janus check` reads an arrival and writes only its own log. Hermes moves files; Zeus deploys. Nothing of Janus runs while idle: `check` runs when Hermes calls it, the map probe runs from a timer every few minutes and exits.

On the server Janus is one file, a Python 3 zipapp with no dependencies (`bash scripts/build.sh` → `dist/janus`). It calls `tailscale`, which the server already has.

## Repository
`docs/design.md` is the design: decisions, the policy file (`routes.json`: who may send what), every check and its reason text, archives and folders, Zeus approvals, the doors file (`doors.json`: what should be open), the Map page and its accessibility rules, logs, and the build order. `janus/` is the package, `plugin/` the Elaia page, `units/` the systemd units, `scripts/` build, install and the privacy check, `tests/` the tests (`bash tests/run.sh`, with a fake `tailscale` in `tests/fixtures/`).

Public text uses placeholders (`{{SERVER}}`, `{{PC}}`, `{{PHONE}}`, `{{SSH}}`, `{{HOME_PC}}`, `{{HOME_SERVER}}`) and never a real device, user, path or host; `scripts/check-private.sh` enforces that before every push. MIT licence.
