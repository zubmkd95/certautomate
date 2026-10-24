import argparse
import secrets
import sys
from pathlib import Path

import yaml

from . import __version__, notify
from .ca import CA
from .clearpass import ClearPass
from .fortigate import FortiGate
from .monitor import days_left, live_not_after, local_not_after


def load(path):
    with open(path) as f:
        cfg = yaml.safe_load(f)
    for k in ("ca", "targets"):
        if k not in cfg:
            sys.exit(f"config error: missing '{k}' section")
    return cfg


def find(cfg, name):
    for t in cfg["targets"]:
        if t["name"] == name:
            return t
    sys.exit(f"unknown target '{name}'. Known: {', '.join(t['name'] for t in cfg['targets'])}")


def issue_target(ca: CA, t, dry_run=False):
    if dry_run:
        print(f"  [dry-run] would issue cert for CN={t['common_name']} SANs={t.get('sans')}")
        return
    ekus = tuple(t.get("ekus", ["serverAuth"]))
    ca.issue(t["name"], t["common_name"], t.get("sans", [f"DNS:{t['common_name']}"]),
             days=t.get("days"), ekus=ekus)
    ca.verify(t["name"])
    print(f"  issued + verified certificate for {t['name']}")


def deploy_target(ca: CA, t, dry_run=False):
    d = ca.issued_dir / t["name"]
    if not dry_run and not (d / "cert.pem").exists():
        raise RuntimeError(f"nothing issued yet for {t['name']}; run `issue {t['name']}` first")
    if t["type"] == "fortigate":
        fg = FortiGate(t)
        if dry_run:
            fg.deploy("", "", "", dry_run=True)
        else:
            ca_pem = ca.cert.read_text()
            if ca.chain_extra:
                ca_pem = ca.chain_extra.read_text().rstrip() + "\n" + ca_pem
            fg.deploy((d / "cert.pem").read_text(), (d / "key.pem").read_text(), ca_pem)
    elif t["type"] == "clearpass":
        cp = ClearPass(t)
        if dry_run:
            cp.deploy(d / "bundle.p12", "x", dry_run=True)
        else:
            pw = secrets.token_urlsafe(24)
            p12 = ca.make_p12(t["name"], pw)
            cp.deploy(p12, pw)
            p12.unlink(missing_ok=True)  # don't leave a bundle lying around
    else:
        raise ValueError(f"unknown target type {t['type']}")


def status_rows(cfg, ca):
    rows = []
    for t in cfg["targets"]:
        loc = local_not_after(ca, t["name"])
        live = live_not_after(t["host"], t.get("port", 443))
        rows.append((t["name"], t["type"], t["host"],
                     days_left(loc) if loc else None, days_left(live) if live else None))
    return rows


def cmd_status(cfg, ca, a):
    fmt = "{:<14}{:<11}{:<22}{:<16}{:<16}"
    print(fmt.format("TARGET", "TYPE", "HOST", "LOCAL(days)", "LIVE(days)"))
    bad = False
    thr = int(cfg.get("renew_before_days", 30))
    for n, ty, h, l, v in status_rows(cfg, ca):
        flag = ""
        if (l is not None and l < thr) or (v is not None and v < thr) or (l is None and v is None):
            flag, bad = "  <-- ATTENTION", True
        print(fmt.format(n, ty, h, "n/a" if l is None else l, "unreachable" if v is None else v) + flag)
    return 1 if bad else 0


def cmd_renew(cfg, ca, a):
    thr = int(cfg.get("renew_before_days", 30))
    failures, renewed = [], []
    for t in cfg["targets"]:
        if a.target and t["name"] != a.target:
            continue
        loc = local_not_after(ca, t["name"])
        live = live_not_after(t["host"], t.get("port", 443))
        due = a.force or loc is None or days_left(loc) < thr or (live is not None and days_left(live) < thr)
        print(f"[{t['name']}] local={days_left(loc) if loc else 'none'}d live={days_left(live) if live else '?'}d "
              f"-> {'RENEW' if due else 'ok'}")
        if not due:
            continue
        try:
            issue_target(ca, t, a.dry_run)
            deploy_target(ca, t, a.dry_run)
            renewed.append(t["name"])
        except Exception as e:
            print(f"  FAILED: {e}")
            failures.append(f"{t['name']}: {e}")
    if not a.dry_run:
        if failures:
            notify.send(cfg.get("notify"), "certops: renewal FAILED", "\n".join(failures))
        elif renewed:
            notify.send(cfg.get("notify"), "certops: certificates renewed", ", ".join(renewed))
    return 1 if failures else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="certops", description="Internal-CA certificate automation for FortiGate + ClearPass")
    p.add_argument("-c", "--config", default="config.yaml")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init-ca", help="create a new root CA (skip if you already have one)")
    s.add_argument("--cn", default="Internal Root CA")
    s.add_argument("--days", type=int, default=3650)
    s.add_argument("--key-type", default="rsa4096", choices=["rsa4096", "rsa2048", "ecdsa-p384", "ecdsa-p256"])

    s = sub.add_parser("issue", help="issue (and deploy) a certificate for one target")
    s.add_argument("target")
    s.add_argument("--no-deploy", action="store_true")
    s.add_argument("--dry-run", action="store_true")

    s = sub.add_parser("deploy", help="deploy the already-issued certificate for a target")
    s.add_argument("target")
    s.add_argument("--dry-run", action="store_true")

    s = sub.add_parser("renew", help="renew + deploy anything expiring soon (run this from cron/systemd)")
    s.add_argument("--target")
    s.add_argument("--force", action="store_true")
    s.add_argument("--dry-run", action="store_true")

    sub.add_parser("status", help="show expiry (local files and live endpoints)")

    a = p.parse_args(argv)
    cfg = load(a.config)
    ca = CA(cfg["ca"])

    try:
        if a.cmd == "init-ca":
            ca.init(a.cn, a.days, a.key_type)
            print(f"CA created: {ca.cert}\nImport this certificate into your clients/devices as a trusted root.")
            return 0
        if a.cmd == "issue":
            t = find(cfg, a.target)
            issue_target(ca, t, a.dry_run)
            if not a.no_deploy:
                deploy_target(ca, t, a.dry_run)
            return 0
        if a.cmd == "deploy":
            deploy_target(ca, find(cfg, a.target), a.dry_run)
            return 0
        if a.cmd == "renew":
            return cmd_renew(cfg, ca, a)
        if a.cmd == "status":
            return cmd_status(cfg, ca, a)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
