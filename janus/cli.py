"""The janus command line: check, verify-approval, map, ack, check-config, seen. Each issue adds its part."""
import argparse
import sys

from janus import approvals, check, config, mapper, seen, version

DESCRIPTION = ("Janus is the door: he checks every Hermes delivery before it lands and draws which doors of the "
               "tailnet are open. He never carries, moves, unpacks or runs anything.")


def check_config(args):
    """janus check-config: one sentence per route and device, then the warnings and errors; exit 1 on errors."""
    cfg = config.check(args.routes, doors=args.doors, hermes=args.hermes)
    for line in cfg.explain():
        print(line)
    for w in cfg.warnings:
        print("warning: " + w, file=sys.stderr)
    for e in cfg.errors:
        print("error: " + e, file=sys.stderr)
    if cfg.errors:
        print("%s: %s. Fix them; Janus passes nothing until the config is right."
              % (cfg.what, config.plural(len(cfg.errors), "error")), file=sys.stderr)
        return 1
    w = len(cfg.warnings)
    print("%s: %s, %s ok%s" % (cfg.what, config.plural(len(cfg.routes), "route"), config.plural(len(cfg.devices), "device"),
                               ", %s" % config.plural(w, "warning") if w else ""))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="janus", description=DESCRIPTION)
    parser.add_argument("--version", action="version", version="janus " + version())
    sub = parser.add_subparsers(dest="command", title="commands", metavar="<command>")
    p = sub.add_parser("check-config", help="read routes.json and doors.json, say what each allows, and list what is wrong")
    p.add_argument("--routes", metavar="FILE", help="the routes file (default: $JANUS_CONFIG or " + config.ROUTES + ")")
    p.add_argument("--doors", metavar="FILE", help="the doors file (default: $JANUS_DOORS or " + config.DOORS + ")")
    p.add_argument("--hermes", metavar="FILE", help="Hermes's routes file, to warn about routes Janus doesn't know "
                                                    "(default: $HERMES_CONFIG or " + config.HERMES_CONFIG + ")")
    p.set_defaults(func=check_config)
    p = sub.add_parser("check", help="check one arrival from Hermes: exit 0 pass, 10 quarantine, 11 duplicate, 2 failed")
    p.add_argument("--json", action="store_true", help="the verdict as one JSON object on stdout (what Hermes reads)")
    p.add_argument("arrival", help="the arrival folder: meta.json and data")
    p.set_defaults(func=check.main)
    p = sub.add_parser("verify-approval", help="answer Zeus: is this approval from an allowed person on an allowed device? "
                                               "(the request on stdin, the answer on stdout; exit 0 allowed, 10 refused, 2 failed)")
    p.add_argument("--routes", metavar="FILE", help="a routes file to judge by instead of the installed one")
    p.set_defaults(func=approvals.main)
    p = sub.add_parser("map", help="probe the doors of the tailnet and write map.json when something changed "
                                   "(janus-map.timer runs it; exit 0 the run completed, 2 it could not be made)")
    p.add_argument("--json", action="store_true", help="the map as one JSON object on stdout")
    p.add_argument("--once", action="store_true", help="one run now: what a run always is (the Map page's Probe now says it)")
    p.set_defaults(func=mapper.main)
    p = sub.add_parser("ack", help="mark the doors closed unexpectedly right now as seen: Argus stops glaring about them until "
                                   "one of them changes (exit 0 done or nothing to mark, 2 map.json is broken)",
                    description="Mark the doors closed unexpectedly right now as seen: they go into alert.acked of map.json "
                                "and the alert file is removed, so Argus stops glaring about them. A door that changes "
                                "(reopens, its room falls asleep, it leaves doors.json) is no longer marked, so a later "
                                "close alerts again. Exit 0 when done or when there was nothing to mark, 2 when map.json "
                                "is broken (nothing is written).")
    p.set_defaults(func=mapper.ack_main)
    p = sub.add_parser("seen", help="the hashes Janus has passed: list them, or forget one")
    p.add_argument("action", choices=("list", "forget"))
    p.add_argument("hash", nargs="?")
    p.set_defaults(func=seen.main)
    return parser


def main(argv=None):
    """Run the command line; returns the exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    return args.func(args)
