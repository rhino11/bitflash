#!/usr/bin/env python3
"""Build a static Bitflash block explorer from local blk*.dat files."""

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

import bitflash_chain as chain


ADDRESS_VERSION = 25
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    v = bytes([ADDRESS_VERSION]) + payload
    v += chain.sha256d(v)[:4]
    n = int.from_bytes(v, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = B58[r] + s
    for byte in v:
        if byte == 0:
            s = "1" + s
        else:
            break
    return s


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def spk_info(script_hex):
    try:
        spk = bytes.fromhex(script_hex)
    except ValueError:
        return {"type": "malformed", "hex": script_hex[:80]}
    if (
        len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9
        and spk[2] == 0x14 and spk[23] == 0x88 and spk[24] == 0xAC
    ):
        return {"type": "p2pkh", "address": b58check(spk[3:23])}
    if len(spk) >= 35 and spk[-1] == 0xAC:
        if spk[0] == 0x41 and len(spk) == 67:
            pk = spk[1:66]
            return {"type": "p2pk", "pubkey": pk.hex(), "address": b58check(hash160(pk))}
        if spk[0] == 0x21 and len(spk) == 35:
            pk = spk[1:34]
            return {"type": "p2pk", "pubkey": pk.hex(), "address": b58check(hash160(pk))}
    return {"type": "other", "hex": script_hex[:80]}


def explorer_tx(tx):
    vin = []
    for txin in tx["vin"]:
        coinbase = (
            txin["prevout_hash"] == "0" * 64
            and txin["prevout_n"] == 0xFFFFFFFF
        )
        vin.append({
            "coinbase": coinbase,
            "prev": None if coinbase else txin["prevout_hash"],
            "vout": None if coinbase else txin["prevout_n"],
        })
    vout = []
    for out in tx["vout"]:
        vout.append(dict({"value": out["value_satoshis"]}, **spk_info(out["script_pub_key_hex"])))
    return {"txid": tx["txid"], "vin": vin, "vout": vout, "size": len(chain.ser_tx(tx))}


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--datadir", help="Bitflash data directory containing blk*.dat")
    ap.add_argument("--max-blocks", type=int, default=0,
                    help="number of blocks to scan; 0 means all block files")
    ap.add_argument("paths", nargs="+",
                    help="with --datadir: <out-dir>; otherwise: <blk*.dat>... <out-dir>")
    args = ap.parse_args(argv)
    if args.datadir:
        if len(args.paths) != 1:
            raise SystemExit("usage with --datadir: build-explorer.py --datadir DATADIR <out-dir>")
        args.block_files = None
        args.out_dir = args.paths[0]
    else:
        if len(args.paths) < 2:
            raise SystemExit("usage: build-explorer.py <blk*.dat>... <out-dir>")
        args.block_files = args.paths[:-1]
        args.out_dir = args.paths[-1]
    return args


def load_blocks(args):
    if args.datadir:
        return chain.read_blocks(args.datadir, args.max_blocks)
    return chain.read_blocks_from_files(args.block_files, args.max_blocks)


def build_explorer(raw_blocks, out_dir):
    try:
        blocks = chain.select_main_chain(raw_blocks)
    except chain.ParseError as e:
        raise SystemExit(str(e))
    out = Path(out_dir)
    # Wipe any previous block files so a change in layout (or a shrinking chain)
    # never leaves stale files behind and blows past the Pages file cap.
    shutil.rmtree(out / "block", ignore_errors=True)
    (out / "block").mkdir(parents=True, exist_ok=True)

    BLOCK_CHUNK = 1000  # blocks per file; keeps the deploy well under Cloudflare Pages' 20k-file cap
    summaries = []
    chunks = {}
    for height, block in enumerate(blocks):
        txs = [explorer_tx(tx) for tx in block["transactions"]]
        detail = {
            "height": height,
            "hash": block["hash"],
            "prev": block["previous_hash"],
            "merkleRoot": block["merkle_root"],
            "version": block["version"],
            "time": block["time"],
            "bits": int(block["bits"], 16),
            "nonce": block["nonce"],
            "size": block["size"],
            "txs": txs,
        }
        cb = txs[0]["vout"][0] if txs and txs[0]["vout"] else {}
        summaries.append({
            "height": height,
            "hash": block["hash"],
            "time": block["time"],
            "nTx": len(txs),
            "size": block["size"],
            "cbValue": cb.get("value", 0),
            "cbAddr": cb.get("address", ""),
        })
        chunks.setdefault(height // BLOCK_CHUNK, {})[str(height)] = detail

    for ci, group in chunks.items():
        (out / "block" / ("%d.json" % ci)).write_text(
            json.dumps(group, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )

    summaries.sort(key=lambda x: -x["height"])
    (out / "blocks.json").write_text(
        json.dumps({
            "network": "bitflash",
            "tipHeight": len(blocks) - 1,
            "count": len(blocks),
            "blocks": summaries,
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    (out / "index.html").write_text(INDEX_HTML, encoding="utf-8")
    (out / "style.css").write_text(STYLE_CSS, encoding="utf-8")
    (out / "explorer.js").write_text(EXPLORER_JS, encoding="utf-8")
    logo = Path(__file__).resolve().parents[1] / "docs" / "logo.png"
    if logo.exists():
        shutil.copyfile(logo, out / "logo.png")
    return len(blocks), len(blocks) - 1


def main(argv):
    args = parse_args(argv)
    raw_blocks = load_blocks(args)
    if not raw_blocks:
        raise SystemExit("no Bitflash blocks parsed")
    count, tip = build_explorer(raw_blocks, args.out_dir)
    print("explorer built: %d main-chain blocks, tip %d, into %s" % (count, tip, args.out_dir))
    return 0


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bitflash Block Explorer</title>
<meta name="description" content="Read-only Bitflash block explorer generated from local blk*.dat files.">
<link rel="icon" href="logo.png" type="image/png">
<link rel="stylesheet" href="style.css">
<script src="explorer.js" defer></script>
</head>
<body>
<header class="topbar">
  <a class="brand" href="https://bitflash.network/"><img src="logo.png" width="22" height="22" alt="">Bitflash</a>
  <nav aria-label="Bitflash sites">
    <a href="https://bitflash.network/">home</a>
    <a href="https://git.bitflash.network/bitflash/bitflash">code</a>
    <a href="https://docs.bitflash.network/">docs</a>
    <a href="https://releases.bitflash.network/">downloads</a>
    <a href="https://explorer.bitflash.network/" aria-current="page">explorer</a>
    <a href="https://status.bitflash.network/">status</a>
    <a href="https://faucet.bitflash.network/">faucet</a>
  </nav>
  <span class="meta" id="tip"></span>
</header>
<div class="wrap">
  <h1>Block explorer <button class="link" id="home" hidden>back to blocks</button></h1>
  <p class="note">Read-only view of the main chain: blocks, their transactions, and the coinbase payout. There is no mempool and no per-address history here.</p>
  <div id="listview">
    <input id="q" placeholder="Search by height or block hash">
    <div class="scroll"><table>
      <thead><tr><th>Height</th><th>Time (UTC)</th><th>Txs</th><th>Size</th><th>Coinbase</th><th>To</th></tr></thead>
      <tbody id="rows"></tbody>
    </table></div>
    <p class="mut" id="more"></p>
  </div>
  <div id="detail" hidden></div>
</div>
</body>
</html>
"""


STYLE_CSS = r""":root{
  color-scheme: light dark;
  --bg:#fff; --bg-2:#f6f6f6; --fg:#111; --dim:#6b6b6b; --line:#d7d7d7; --line-hard:#111;
  --accent:#0b7a34; --accent-2:#12a047; --bar:3rem;
  --mono: ui-monospace,"Cascadia Mono","Segoe UI Mono",Consolas,"DejaVu Sans Mono","Liberation Mono","Courier New",monospace;
}
@media (prefers-color-scheme: dark){:root{
  --bg:#000; --bg-2:#0b0b0b; --fg:#dcdcdc; --dim:#8a8a8a; --line:#242424; --line-hard:#4a4a4a;
  --accent:#2ee06a; --accent-2:#6bff9f;
}}
*{box-sizing:border-box;}
html,body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 var(--mono);-webkit-text-size-adjust:100%;}
a{color:var(--accent);}
.topbar{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;min-height:var(--bar);
        padding:.5rem clamp(.9rem,2.5vw,3rem);border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:5;}
.brand{display:flex;align-items:center;gap:.6rem;text-decoration:none;color:var(--fg);font-weight:bold;}
.brand img{width:22px;height:22px;display:block;}
.topbar nav{display:flex;flex-wrap:wrap;gap:.15rem 1.4rem;font-size:.86rem;}
.topbar nav a{text-decoration:none;color:var(--dim);}
.topbar nav a::before{content:"/";color:var(--line-hard);margin-right:.3rem;}
.topbar nav a:hover{color:var(--fg);text-decoration:underline;}
.topbar nav a[aria-current="page"]{color:var(--accent);font-weight:bold;}
.topbar nav a[aria-current="page"]::before{color:var(--accent);}
.topbar .meta{margin-left:auto;font-size:.76rem;color:var(--dim);letter-spacing:.06em;}
.wrap{padding:1.4rem clamp(.9rem,2.5vw,3rem) 4rem;}
h1{font-size:1rem;margin:0 0 .3rem;letter-spacing:.02em;}
h2{font-size:.95rem;margin:1.2rem 0 .4rem;}
.mut{color:var(--dim);}
.note{color:var(--dim);font-size:.82rem;max-width:60rem;margin:.2rem 0 1rem;}
input{width:100%;max-width:28rem;padding:.5rem .7rem;border:1px solid var(--line);background:var(--bg-2);color:var(--fg);font:inherit;font-size:.86rem;}
input:focus{outline:none;border-color:var(--accent);}
.scroll{overflow-x:auto;}
table{width:100%;border-collapse:collapse;margin-top:.8rem;font-size:.86rem;}
th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--line);font-variant-numeric:tabular-nums;}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;color:var(--dim);font-weight:normal;}
tr.blk{cursor:pointer;}
tr.blk:hover td{background:var(--bg-2);}
code{font-size:.8rem;word-break:break-all;color:var(--fg);}
.card{border:1px solid var(--line);background:var(--bg-2);padding:.9rem 1rem;margin-top:.8rem;}
.kv{display:grid;grid-template-columns:11rem 1fr;gap:.25rem .8rem;font-size:.82rem;}
.kv div:nth-child(odd){color:var(--dim);}
.tx{border-top:1px solid var(--line);padding:.7rem 0;}
.io{display:grid;grid-template-columns:1fr 1fr;gap:1rem;}
@media (max-width:640px){.io{grid-template-columns:1fr;}.kv{grid-template-columns:7rem 1fr;}.topbar .meta{margin-left:0;width:100%;}}
.pill{display:inline-block;font-size:.68rem;padding:.05rem .5rem;border:1px solid var(--line);color:var(--dim);text-transform:uppercase;letter-spacing:.05em;}
button.link{background:none;border:none;color:var(--accent);cursor:pointer;font:inherit;padding:0;text-decoration:underline;}
"""


EXPLORER_JS = r"""
var SUM = [], SHOWN = 200;
function btf(sat){ return (sat/1e8).toFixed(8).replace(/0+$/,'').replace(/\.$/,'')+" BTF"; }
function ts(t){ return new Date(t*1000).toISOString().replace('T',' ').replace('.000Z',' UTC'); }
function short(h){ return h ? h.slice(0,10)+"..."+h.slice(-6) : "-"; }
function E(tag, cls, text){
  var e = document.createElement(tag);
  if(cls) e.className = cls;
  if(text !== undefined) e.textContent = text;
  return e;
}
function code(text){ return E('code', '', text); }
function clear(e){ while(e.firstChild) e.removeChild(e.firstChild); }
function append(parent){
  for(var i=1;i<arguments.length;i++) parent.appendChild(arguments[i]);
  return parent;
}
function row(cells, cls){
  var tr = E('tr', cls || '');
  cells.forEach(function(c){ append(tr, E('td', '', c)); });
  return tr;
}
function renderList(filter){
  var q=(filter||"").trim().toLowerCase(), rows=document.getElementById('rows');
  clear(rows);
  var list = q ? SUM.filter(function(b){ return String(b.height)===q || b.hash.indexOf(q)===0; }) : SUM.slice(0,SHOWN);
  if(!list.length){
    var empty = E('tr');
    var td = E('td', 'mut', 'no match');
    td.colSpan = 6;
    append(empty, td); append(rows, empty);
  }
  list.forEach(function(b){
    var tr = row([String(b.height), ts(b.time), String(b.nTx), b.size+' B', btf(b.cbValue), ''], 'blk');
    tr.dataset.h = b.height;
    clear(tr.children[5]);
    append(tr.children[5], code(b.cbAddr || '-'));
    tr.onclick = function(){ openBlock(tr.dataset.h); };
    append(rows, tr);
  });
  document.getElementById('more').textContent = (!q && SUM.length>SHOWN) ? ("showing latest "+SHOWN+" of "+SUM.length+" blocks; search to find any") : "";
}
function kv(parent, key, value, isCode){
  append(parent, E('div', '', key));
  append(parent, isCode ? append(E('div'), code(value)) : E('div', '', value));
}
function ioSide(title, items, render){
  var side = E('div');
  append(side, E('div', 'mut', title));
  items.forEach(function(item){ append(side, render(item)); });
  return side;
}
function openBlock(h){
  fetch('block/'+Math.floor(h/1000)+'.json').then(function(r){return r.json();}).then(function(chunk){
    var b=chunk[h];
    if(!b){var dd=document.getElementById('detail');clear(dd);append(dd,E('h2','','Block '+h+' not found'));return;}
    var detail = document.getElementById('detail');
    clear(detail);
    append(detail, E('h2', '', 'Block '+b.height));
    var card = E('div', 'card'), grid = E('div', 'kv');
    kv(grid, 'Height', String(b.height));
    kv(grid, 'Hash', b.hash, true);
    var prev = E('div');
    if(b.height > 0){
      var btn = E('button', 'link');
      append(btn, code(short(b.prev)));
      btn.onclick = function(){ openBlock(b.height - 1); };
      append(prev, btn);
    } else {
      append(prev, code(short(b.prev)));
    }
    append(grid, E('div', '', 'Previous'), prev);
    kv(grid, 'Merkle root', b.merkleRoot, true);
    kv(grid, 'Time (UTC)', ts(b.time));
    kv(grid, 'Bits / Nonce', b.bits.toString(16)+' / '+b.nonce);
    kv(grid, 'Size / Txs', b.size+' B / '+b.txs.length);
    append(card, grid); append(detail, card);
    b.txs.forEach(function(t, i){
      var tx = E('div', 'tx');
      var head = E('div');
      append(head, code(t.txid));
      if(i === 0) append(head, E('span', 'pill', 'coinbase'));
      var io = E('div', 'io');
      append(io, ioSide('Inputs', t.vin, function(v){
        var d = E('div');
        if(v.coinbase) append(d, E('span', 'pill', 'coinbase'));
        else append(d, code(short(v.prev)+':'+v.vout));
        return d;
      }));
      append(io, ioSide('Outputs', t.vout, function(o){
        var d = E('div');
        var to = o.address ? o.address : (o.pubkey ? 'pubkey '+o.pubkey.slice(0,16)+'...' : o.type);
        append(d, document.createTextNode(btf(o.value)+' -> '), code(to));
        return d;
      }));
      append(tx, head, io); append(detail, tx);
    });
    document.getElementById('listview').hidden = true;
    detail.hidden = false;
    document.getElementById('home').hidden = false;
    window.scrollTo(0,0);
  });
}
document.getElementById('home').onclick=function(){
  document.getElementById('detail').hidden = true;
  document.getElementById('listview').hidden = false;
  this.hidden = true;
};
document.getElementById('q').oninput=function(){ renderList(this.value); };
fetch('blocks.json').then(function(r){return r.json();}).then(function(d){
  SUM=d.blocks; document.getElementById('tip').textContent='tip height '+d.tipHeight+' - '+d.count+' blocks';
  renderList('');
});
"""


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
