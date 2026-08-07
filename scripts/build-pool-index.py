#!/usr/bin/env python3
#
# Build a static public pool directory from one or more Bitflash pool_status.json
# files. Inputs may be local paths or http(s) URLs.

import argparse
import html
import json
import os
import time
import urllib.request


def load_json(source):
    if source.startswith("http://") or source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=10) as r:
            return json.loads(r.read().decode("utf-8"))
    with open(source, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def normalize_pool(source, obj, now):
    operator = obj.get("operator", {})
    pool = obj.get("pool", {})
    node = obj.get("node", {})
    updated = int(obj.get("updatedAt") or 0)
    age = max(0, now - updated) if updated else None
    online = bool(node.get("poolRunning")) and age is not None and age <= 120
    return {
        "source": source,
        "name": operator.get("name") or "Bitflash Pool",
        "btfAddress": operator.get("btfAddress") or "",
        "feePercent": float(operator.get("feePercent") or 0.0),
        "dashboardUrl": operator.get("dashboardUrl") or "",
        "height": int(node.get("height") or 0),
        "online": online,
        "ageSeconds": age,
        "authorizedMiners": int(pool.get("authorizedMiners") or 0),
        "blocksFoundSession": int(pool.get("blocksFoundSession") or 0),
        "roundShares": int(pool.get("roundShares") or 0),
        "hashRate": float(pool.get("hashRate") or 0.0),
    }


def rank_key(pool):
    return (
        1 if pool["online"] else 0,
        pool["hashRate"],
        pool["authorizedMiners"],
        -pool["feePercent"],
        pool["name"].lower(),
    )


def render_html(pools, generated_at):
    rows = []
    for p in pools:
        dash = p["dashboardUrl"]
        # Only linkify http(s). The dashboard URL comes from an operator's
        # self-published status file, so a "javascript:" or "data:" scheme
        # would become a clickable script-injection on this public page.
        dash_lower = dash.lower()
        if dash_lower.startswith("http://") or dash_lower.startswith("https://"):
            dash_html = '<a href="{0}" rel="noopener noreferrer">dashboard</a>'.format(
                html.escape(dash, quote=True))
        else:
            dash_html = "-"
        rows.append(
            "<tr>"
            "<td>{status}</td>"
            "<td><strong>{name}</strong><br><code>{addr}</code></td>"
            "<td>{fee:.2f}%</td>"
            "<td>{miners}</td>"
            "<td>{hashrate:.2f}</td>"
            "<td>{blocks}</td>"
            "<td>{height}</td>"
            "<td>{age}</td>"
            "<td>{dash}</td>"
            "</tr>".format(
                status="online" if p["online"] else "stale",
                name=html.escape(p["name"]),
                addr=html.escape(p["btfAddress"]),
                fee=p["feePercent"],
                miners=p["authorizedMiners"],
                hashrate=p["hashRate"],
                blocks=p["blocksFoundSession"],
                height=p["height"],
                age="{}s".format(p["ageSeconds"]) if p["ageSeconds"] is not None else "-",
                dash=dash_html,
            )
        )

    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bitflash Pools</title>
  <style>
    body {{ font: 15px/1.45 system-ui, sans-serif; margin: 32px; color: #111; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
    code {{ font-size: 12px; word-break: break-all; }}
    .note {{ color: #555; max-width: 780px; }}
  </style>
</head>
<body>
  <h1>Bitflash Pools</h1>
  <p class="note">This directory is informational. Bitflash nodes discover pools through Nostr and .btf; this page only helps humans compare public operators.</p>
  <table>
    <thead>
      <tr><th>Status</th><th>Pool</th><th>Fee</th><th>Miners</th><th>H/s</th><th>Blocks</th><th>Height</th><th>Age</th><th>Link</th></tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
  <p class="note">Generated at {generated_at}. JSON: <a href="pools.json">pools.json</a>.</p>
</body>
</html>
""".format(rows="\n      ".join(rows), generated_at=generated_at)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="pool-site")
    ap.add_argument("sources", nargs="+", help="pool_status.json paths or URLs")
    args = ap.parse_args()

    now = int(time.time())
    pools = []
    errors = []
    for source in args.sources:
        try:
            pools.append(normalize_pool(source, load_json(source), now))
        except Exception as e:
            errors.append({"source": source, "error": str(e)})

    pools.sort(key=rank_key, reverse=True)
    os.makedirs(args.out_dir, exist_ok=True)

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    with open(os.path.join(args.out_dir, "pools.json"), "w", encoding="utf-8") as f:
        json.dump({
            "schema": "bitflash-pool-directory-1",
            "generatedAt": generated_at,
            "pools": pools,
            "errors": errors,
        }, f, indent=2, sort_keys=True)
        f.write("\n")

    with open(os.path.join(args.out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(render_html(pools, generated_at))


if __name__ == "__main__":
    main()
