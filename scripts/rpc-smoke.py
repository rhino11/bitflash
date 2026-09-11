"""Exercise the JSON-RPC server the way an exchange integration would.

    python3 scripts/rpc-smoke.py URL USER PASSWORD [BLOCK1_HASH]

Point it at a node started with -rpcuser/-rpcpassword. It reads, lists and
validates; the one call that spends, sendtoaddress, is made against a fresh
address of the node's own wallet, so at worst it moves coins from the wallet to
itself. Run it against a testnet node anyway.
"""
import base64
import json
import sys
import urllib.request

if len(sys.argv) < 4:
    sys.exit(__doc__)
URL = sys.argv[1]
AUTH = base64.b64encode(("%s:%s" % (sys.argv[2], sys.argv[3])).encode()).decode()


def call(method, params=None, auth=AUTH, raw=None):
    body = raw if raw is not None else json.dumps(
        {"id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    if auth:
        req.add_header("Authorization", "Basic " + auth)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def show(label, status, d, keys=None):
    if d is None:
        print("%-34s HTTP %s" % (label, status))
        return
    if d.get("error"):
        print("%-34s erro: %s" % (label, d["error"]["message"]))
        return
    r = d["result"]
    if keys and isinstance(r, dict):
        r = {k: r.get(k) for k in keys}
    s = json.dumps(r)
    print("%-34s %s" % (label, s[:150] + ("..." if len(s) > 150 else "")))


blk1 = sys.argv[4] if len(sys.argv) > 4 else call("getblockhash", [1])[1]["result"]

s, d = call("getblock", [blk1])
show("getblock 1", s, d, ["height", "confirmations", "tx", "previousblockhash"])

s, d = call("getnewaddress")
mine = d["result"]
show("getnewaddress", s, d)
show("validateaddress (mine)", *call("validateaddress", [mine]))
show("validateaddress (faucet's)", *call("validateaddress", ["BBF2iJTA4CCM9hyvWfe3W5iPeujwxS42kG"]))
show("validateaddress (garbage)", *call("validateaddress", ["naoehendereco"]))

show("getbalance", *call("getbalance"))
show("getbalance minconf=1", *call("getbalance", [1]))

s, d = call("listtransactions", [3])
print("%-34s %d entradas" % ("listtransactions 3", len(d["result"])))
t = d["result"][-1]
print("   ultima: %s" % json.dumps({k: t.get(k) for k in ("amount", "confirmations", "generated")}))
print("   details: %s" % json.dumps(t["details"]))

s, d = call("listsinceblock", [""])
r = d["result"]
print("%-34s %d transacoes, lastblock %s..." % ("listsinceblock (tudo)", len(r["transactions"]), r["lastblock"][:12]))
s, d = call("listsinceblock", [blk1])
print("%-34s %d transacoes (so depois do bloco 1)" % ("listsinceblock (desde bloco 1)", len(d["result"]["transactions"])))

txid = t["txid"]
show("gettransaction", *call("gettransaction", [txid]), ["txid", "amount", "confirmations"])
show("gettransaction (desconhecida)", *call("gettransaction", ["00" * 32]))

show("sendtoaddress (saldo 0)", *call("sendtoaddress", [mine, 1.0]))
show("sendtoaddress (endereco lixo)", *call("sendtoaddress", ["lixo", 1.0]))
show("metodo inexistente", *call("nope"))

print()
print("--- seguranca ---")
show("sem auth", *call("getinfo", auth=None))
bad = base64.b64encode(("%s:definitely-not-the-password" % sys.argv[2]).encode()).decode()
show("senha errada", *call("getinfo", auth=bad))
show("json invalido", *call(None, raw=b"{not json"))
s, d = call(None, raw=json.dumps([
    {"id": "a", "method": "getblockcount", "params": []},
    {"id": "b", "method": "getblockhash", "params": [0]},
]).encode())
print("%-34s %s" % ("batch de 2", json.dumps([x.get("result") for x in d])[:100]))
