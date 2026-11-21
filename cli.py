"""
SentinelShield command-line interface.

Runs the detection engine headless — on a server, in a cron job or in a
CI pipeline — with no dashboard and no extra dependencies.

Examples
--------
    python cli.py scan "id=1' OR '1'='1"
    python cli.py inspect --curl "curl 'http://x/?q=<script>alert(1)</script>'"
    python cli.py analyze-log data/sample_access.log
    python cli.py benchmark
    python cli.py simulate --all
    python cli.py metrics

Exit codes: 0 = clean / success, 1 = malicious detected (useful as a CI
gate), 2 = usage error.
"""

import argparse
import json
import sys

import detector
import metrics as metrics_mod
from config import apply_rule_config, load_config
from engine import SCENARIOS, WAFEngine, run_all_scenarios, run_scenario


def _print(obj, as_json):
    if as_json:
        print(json.dumps(obj, indent=2, default=str))


def cmd_scan(args):
    result = detector.detect_threat(args.payload)
    if args.json:
        _print(result, True)
    else:
        if result["detected"]:
            print(f"MALICIOUS  [{result['category']}]  score={result.get('score', 0)}  rule={result.get('matched_rule')}")
        else:
            print("CLEAN")
    return 1 if result["detected"] else 0


def cmd_inspect(args):
    if args.curl:
        request = detector.parse_curl(args.curl)
    elif args.raw:
        request = detector.parse_raw_http(args.raw)
    else:
        request = detector.build_request(query=args.payload or "")
    request["ip"] = args.ip
    verdict = detector.inspect_request(request)
    if args.json:
        _print(verdict, True)
    else:
        status = "MALICIOUS" if verdict["detected"] else "CLEAN"
        print(f"{status}  score={verdict['score']}  category={verdict['category']}")
        for m in verdict["matches"]:
            print(f"  - {m['rule_id']} {m['name']} @ {m['location']} :: {m['matched']}")
    return 1 if verdict["detected"] else 0


def cmd_analyze_log(args):
    with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    result = detector.analyze_access_log(text)
    if args.json:
        _print(result, True)
    else:
        print(f"Lines: {result['total_lines']}  Malicious: {result['malicious_lines']}  Unique IPs: {result['unique_ips']}")
        print(f"Brute-force IPs: {len(result['brute_force_ips'])}")
        print("Top attackers:")
        for ip, count in result["top_attackers"]:
            print(f"  {ip:16} {count} malicious requests")
        print("Attack categories:")
        for cat, count in sorted(result["category_counts"].items(), key=lambda x: -x[1]):
            print(f"  {cat:40} {count}")
    return 1 if result["malicious_lines"] else 0


def cmd_benchmark(args):
    result = detector.evaluate_corpus()
    if args.json:
        _print(result, True)
    else:
        print(f"Samples:   {result['total']}")
        print(f"Accuracy:  {result['accuracy'] * 100:.1f}%")
        print(f"Precision: {result['precision'] * 100:.1f}%")
        print(f"Recall:    {result['recall'] * 100:.1f}%")
        print(f"F1:        {result['f1'] * 100:.1f}%")
        print(f"False positives: {result['fp']}   False negatives: {result['fn']}")
    # Fail CI if accuracy regresses.
    return 0 if result["fp"] == 0 and result["recall"] >= 0.95 else 1


def cmd_simulate(args):
    engine = WAFEngine(persist=False)
    if args.all or not args.scenario:
        events = run_all_scenarios(engine, store=False)
    else:
        events = run_scenario(engine, args.scenario, store=False)
    blocked = sum(1 for e in events if e["action"].split(" (")[0] in ("BLOCKED", "BANNED", "RATE LIMITED"))
    if args.json:
        _print({"requests": len(events), "blocked": blocked,
                "events": events}, True)
    else:
        print(f"Replayed {len(events)} requests, {blocked} stopped.")
    return 0


def cmd_metrics(args):
    print(metrics_mod.prometheus_text())
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="sentinelshield", description="SentinelShield WAF CLI")
    p.add_argument("--json", action="store_true", help="JSON output")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a single string")
    s.add_argument("payload")
    s.set_defaults(func=cmd_scan)

    i = sub.add_parser("inspect", help="Inspect a full request")
    i.add_argument("payload", nargs="?", default="")
    i.add_argument("--curl", help="curl command to parse")
    i.add_argument("--raw", help="raw HTTP request to parse")
    i.add_argument("--ip", default="0.0.0.0")
    i.set_defaults(func=cmd_inspect)

    a = sub.add_parser("analyze-log", help="Analyse an access log file")
    a.add_argument("file")
    a.set_defaults(func=cmd_analyze_log)

    b = sub.add_parser("benchmark", help="Run the accuracy benchmark")
    b.set_defaults(func=cmd_benchmark)

    sim = sub.add_parser("simulate", help="Replay attack scenarios")
    sim.add_argument("scenario", nargs="?", choices=list(SCENARIOS.keys()))
    sim.add_argument("--all", action="store_true")
    sim.set_defaults(func=cmd_simulate)

    m = sub.add_parser("metrics", help="Print Prometheus-style metrics")
    m.set_defaults(func=cmd_metrics)
    return p


def main(argv=None):
    # Apply config-file rules so the CLI matches the dashboard's behaviour.
    cfg = load_config()
    apply_rule_config(cfg)
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
