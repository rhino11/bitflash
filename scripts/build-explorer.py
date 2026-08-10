#!/usr/bin/env python3
#
# Build a static Bitflash block explorer (v0) from a node's blk0001.dat.
# Emits into <out-dir>:
#   blocks.json            summary of every main-chain block (newest first)
#   block/<height>.json    full detail per block (header + all txs)
#   index.html             self-contained viewer (vanilla JS, same-origin fetch)
#
# Scope (v0, deliberately): block list, block detail, and coinbase. No mempool,
# no per-address history. On this chain the coinbase payout key rotates every
# block, so an address index would be nearly useless; block-level transparency is
# what lets miners and users confirm the chain is honest.
#
# Usage: build-explorer.py <blk0001.dat> <out-dir>

import sys, os, json, hashlib, struct

MAGIC = bytes([0xbf, 0x20, 0x5c, 0xfd])
ADDRESS_VERSION = 25  # Bitflash addresses start with "B"

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58check(payload):
    v = bytes([ADDRESS_VERSION]) + payload
    v += sha256d(v)[:4]
    n = int.from_bytes(v, 'big')
    s = ""
    while n > 0:
        n, r = divmod(n, 58); s = B58[r] + s
    for byte in v:
        if byte == 0: s = "1" + s
        else: break
    return s

def hash160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

class R:
    def __init__(s, b, o=0): s.b = b; s.o = o
    def u(s, n): v = s.b[s.o:s.o+n]; s.o += n; return v
    def i32(s): return struct.unpack('<i', s.u(4))[0]
    def u32(s): return struct.unpack('<I', s.u(4))[0]
    def i64(s): return struct.unpack('<q', s.u(8))[0]
    def cs(s):
        c = s.b[s.o]; s.o += 1
        if c < 253: return c
        if c == 253: return struct.unpack('<H', s.u(2))[0]
        if c == 254: return struct.unpack('<I', s.u(4))[0]
        return struct.unpack('<Q', s.u(8))[0]
    def script(s): n = s.cs(); return s.u(n)

def spk_info(spk):
    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xa9 and spk[2] == 0x14 and spk[23] == 0x88 and spk[24] == 0xac:
        return {"type": "p2pkh", "address": b58check(spk[3:23])}
    # P2PK: <pubkey> OP_CHECKSIG (65- or 33-byte key)
    if len(spk) >= 35 and spk[-1] == 0xac:
        if spk[0] == 0x41 and len(spk) == 67:
            pk = spk[1:66]; return {"type": "p2pk", "pubkey": pk.hex(), "address": b58check(hash160(pk))}
        if spk[0] == 0x21 and len(spk) == 35:
            pk = spk[1:34]; return {"type": "p2pk", "pubkey": pk.hex(), "address": b58check(hash160(pk))}
    return {"type": "other", "hex": spk.hex()[:80]}

def parse_tx(r):
    start = r.o
    r.i32()
    nin = r.cs(); vin = []
    for _ in range(nin):
        ph = r.u(32); idx = r.u32(); r.script(); r.u32()
        coinbase = (ph == b'\x00' * 32 and idx == 0xffffffff)
        vin.append({"coinbase": coinbase, "prev": (None if coinbase else ph[::-1].hex()), "vout": (None if coinbase else idx)})
    nout = r.cs(); vout = []
    for _ in range(nout):
        val = r.i64(); spk = r.script(); vout.append(dict({"value": val}, **spk_info(spk)))
    r.u32()
    raw = r.b[start:r.o]
    return {"txid": sha256d(raw)[::-1].hex(), "vin": vin, "vout": vout, "size": len(raw)}

def main():
    if len(sys.argv) != 3:
        print("usage: build-explorer.py <blk0001.dat> <out-dir>", file=sys.stderr); sys.exit(2)
    blkpath, out = sys.argv[1], sys.argv[2]
    data = open(blkpath, 'rb').read()
    blocks = {}; o = 0; n = len(data)
    while o + 8 <= n:
        if data[o:o+4] != MAGIC: o += 1; continue
        o += 4; size = struct.unpack('<I', data[o:o+4])[0]; o += 4
        blk = data[o:o+size]; o += size
        if len(blk) < 80: continue
        h = sha256d(blk[:80])[::-1].hex()
        r = R(blk, 0)
        ver = r.i32(); prev = r.u(32)[::-1].hex(); merk = r.u(32)[::-1].hex()
        t = r.u32(); bits = r.u32(); nonce = r.u32()
        ntx = r.cs(); txs = []
        try:
            for _ in range(ntx): txs.append(parse_tx(r))
        except Exception:
            continue
        blocks[h] = {"hash": h, "prev": prev, "merkleRoot": merk, "version": ver,
                     "time": t, "bits": bits, "nonce": nonce, "size": size, "txs": txs}
    if not blocks:
        print("no blocks parsed", file=sys.stderr); sys.exit(1)

    hc = {}
    def height(h):
        chain = []; cur = h
        while cur in blocks and cur not in hc:
            chain.append(cur); cur = blocks[cur]["prev"]
        base = hc.get(cur, 0)
        for hh in reversed(chain): base += 1; hc[hh] = base
        return hc[h]
    for h in blocks: height(h)
    tip = max(blocks, key=lambda h: hc[h])
    chain = []; cur = tip
    while cur in blocks: chain.append(cur); cur = blocks[cur]["prev"]
    chain.reverse()

    os.makedirs(os.path.join(out, "block"), exist_ok=True)
    summaries = []
    for h in chain:
        b = blocks[h]; H = hc[h]
        cb = b["txs"][0]["vout"][0] if b["txs"] and b["txs"][0]["vout"] else {}
        summaries.append({"height": H, "hash": h, "time": b["time"], "nTx": len(b["txs"]),
                          "size": b["size"], "cbValue": cb.get("value", 0), "cbAddr": cb.get("address", "")})
        json.dump(dict({"height": H}, **b), open(os.path.join(out, "block", "%d.json" % H), "w"), separators=(',', ':'))
    summaries.sort(key=lambda x: -x["height"])
    json.dump({"network": "bitflash", "tipHeight": hc[tip], "count": len(chain), "blocks": summaries},
              open(os.path.join(out, "blocks.json"), "w"), separators=(',', ':'))
    open(os.path.join(out, "index.html"), "w").write(INDEX_HTML)
    print("explorer built: %d main-chain blocks, tip %d, into %s" % (len(chain), hc[tip], out))


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bitflash Block Explorer</title>
<style>
  :root { color-scheme: light dark; --bg:#fff; --fg:#111; --mut:#666; --line:#e2e2e2; --card:#fafafa; --acc:#2b6cb0; }
  @media (prefers-color-scheme: dark){ :root{ --bg:#0e0f11; --fg:#e6e6e6; --mut:#9aa0a6; --line:#26282c; --card:#16181b; --acc:#63b3ed; } }
  * { box-sizing: border-box; }
  body { font: 15px/1.5 system-ui, sans-serif; margin:0; background:var(--bg); color:var(--fg); }
  header { padding:20px 24px; border-bottom:1px solid var(--line); display:flex; gap:16px; align-items:baseline; flex-wrap:wrap; }
  h1 { font-size:18px; margin:0; }
  .mut { color:var(--mut); }
  .wrap { padding:16px 24px; max-width:1100px; margin:0 auto; }
  input { width:100%; max-width:420px; padding:9px 12px; border:1px solid var(--line); border-radius:8px; background:var(--card); color:var(--fg); font-size:14px; }
  table { width:100%; border-collapse:collapse; margin-top:12px; }
  th,td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); font-variant-numeric:tabular-nums; }
  th { font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:var(--mut); }
  tr.blk { cursor:pointer; }
  tr.blk:hover td { background:var(--card); }
  code { font-size:12px; word-break:break-all; }
  .scroll { overflow-x:auto; }
  a { color:var(--acc); text-decoration:none; }
  .card { border:1px solid var(--line); border-radius:10px; background:var(--card); padding:14px 16px; margin-top:12px; }
  .kv { display:grid; grid-template-columns:150px 1fr; gap:4px 12px; font-size:13px; }
  .kv div:nth-child(odd){ color:var(--mut); }
  .tx { border-top:1px solid var(--line); padding:10px 0; }
  .io { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  @media (max-width:640px){ .io{ grid-template-columns:1fr; } .kv{ grid-template-columns:110px 1fr; } }
  .pill { display:inline-block; font-size:11px; padding:1px 7px; border-radius:99px; border:1px solid var(--line); color:var(--mut); }
  button.link { background:none; border:none; color:var(--acc); cursor:pointer; font:inherit; padding:0; }
  .note { color:var(--mut); font-size:13px; max-width:820px; }
</style>
</head>
<body>
<header>
  <h1>Bitflash Block Explorer</h1>
  <span class="mut" id="tip"></span>
  <span style="flex:1"></span>
  <button class="link" id="home" style="display:none">back to blocks</button>
</header>
<div class="wrap">
  <p class="note">Read-only view of the main chain: blocks, their transactions, and the coinbase payout. There is no mempool and no per-address history here. On Bitflash the coinbase payout key rotates every block, so an address index would say almost nothing; what matters is that every block and every coinbase is here to check.</p>
  <div id="listview">
    <input id="q" placeholder="Search by height or block hash">
    <div class="scroll"><table>
      <thead><tr><th>Height</th><th>Time (UTC)</th><th>Txs</th><th>Size</th><th>Coinbase</th><th>To</th></tr></thead>
      <tbody id="rows"></tbody>
    </table></div>
    <p class="mut" id="more"></p>
  </div>
  <div id="detail" style="display:none"></div>
</div>
<script>
var SUM = [], BYH = {}, SHOWN = 200;
function btf(sat){ return (sat/1e8).toFixed(8).replace(/0+$/,'').replace(/\.$/,'')+" BTF"; }
function ts(t){ return new Date(t*1000).toISOString().replace('T',' ').replace('.000Z',' UTC'); }
function esc(s){ return String(s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];}); }
function short(h){ return h ? h.slice(0,10)+"…"+h.slice(-6) : "-"; }

function renderList(filter){
  var q=(filter||"").trim().toLowerCase(), rows=document.getElementById('rows'), out="";
  var list = q ? SUM.filter(function(b){ return String(b.height)===q || b.hash.indexOf(q)===0; }) : SUM.slice(0,SHOWN);
  for(var i=0;i<list.length;i++){ var b=list[i];
    out += '<tr class="blk" data-h="'+b.height+'"><td>'+b.height+'</td><td>'+ts(b.time)+'</td><td>'+b.nTx+'</td><td>'+b.size+' B</td><td>'+btf(b.cbValue)+'</td><td><code>'+(b.cbAddr?esc(b.cbAddr):'-')+'</code></td></tr>';
  }
  rows.innerHTML = out || '<tr><td colspan="6" class="mut">no match</td></tr>';
  document.getElementById('more').textContent = (!q && SUM.length>SHOWN) ? ("showing latest "+SHOWN+" of "+SUM.length+" blocks; search to find any") : "";
  Array.prototype.forEach.call(rows.querySelectorAll('tr.blk'), function(tr){ tr.onclick=function(){ openBlock(tr.getAttribute('data-h')); }; });
}
function ioSide(title, items, html){
  var s='<div><div class="mut">'+title+'</div>'; for(var i=0;i<items.length;i++){ s+=html(items[i]); } return s+'</div>';
}
function openBlock(h){
  fetch('block/'+h+'.json').then(function(r){return r.json();}).then(function(b){
    var s='<div class="card"><div class="kv">'+
      '<div>Height</div><div>'+b.height+'</div>'+
      '<div>Hash</div><div><code>'+esc(b.hash)+'</code></div>'+
      '<div>Previous</div><div><button class="link" onclick="openBlock('+(b.height-1)+')"><code>'+esc(short(b.prev))+'</code></button></div>'+
      '<div>Merkle root</div><div><code>'+esc(b.merkleRoot)+'</code></div>'+
      '<div>Time (UTC)</div><div>'+ts(b.time)+'</div>'+
      '<div>Bits / Nonce</div><div>'+b.bits.toString(16)+' / '+b.nonce+'</div>'+
      '<div>Size / Txs</div><div>'+b.size+' B / '+b.txs.length+'</div>'+
      '</div></div>';
    for(var i=0;i<b.txs.length;i++){ var t=b.txs[i];
      s+='<div class="tx"><div><code>'+esc(t.txid)+'</code> '+(i===0?'<span class="pill">coinbase</span>':'')+'</div><div class="io">';
      s+=ioSide('Inputs', t.vin, function(v){ return '<div>'+(v.coinbase?'<span class="pill">coinbase</span>':'<code>'+esc(short(v.prev))+':'+v.vout+'</code>')+'</div>'; });
      s+=ioSide('Outputs', t.vout, function(o){ var to=o.address?esc(o.address):(o.pubkey?'pubkey '+esc(o.pubkey.slice(0,16))+'…':esc(o.type)); return '<div>'+btf(o.value)+' → <code>'+to+'</code></div>'; });
      s+='</div></div>';
    }
    document.getElementById('listview').style.display='none';
    var d=document.getElementById('detail'); d.style.display='block'; d.innerHTML='<h2 style="font-size:16px">Block '+b.height+'</h2>'+s;
    document.getElementById('home').style.display='inline';
    window.scrollTo(0,0);
  });
}
document.getElementById('home').onclick=function(){ document.getElementById('detail').style.display='none'; document.getElementById('listview').style.display='block'; this.style.display='none'; };
document.getElementById('q').oninput=function(){ renderList(this.value); };
fetch('blocks.json').then(function(r){return r.json();}).then(function(d){
  SUM=d.blocks; document.getElementById('tip').textContent='tip height '+d.tipHeight+' · '+d.count+' blocks';
  renderList('');
});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
