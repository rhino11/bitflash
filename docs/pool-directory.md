# Public Pool Directory

`pool.bitflash.network` should be a public directory, not a network dependency.
Nodes discover pools through Nostr and `.btf`; the website only helps humans
compare operators.

Operators can publish the `pool_status.json` file produced by:

```bash
bitflash -nogui -gen -operator -poolstatusfile=/var/www/pool_status.json
```

Build a static directory from one or more status files:

```bash
python3 scripts/build-pool-index.py --out-dir public/pool \
  https://operator-one.example/pool_status.json \
  https://operator-two.example/pool_status.json
```

The generated output contains:

- `index.html`: human-readable ranking page.
- `pools.json`: machine-readable API for `api.bitflash.network/pools.json`.

Ranking order is intentionally simple:

1. online pools first;
2. higher reported hashrate;
3. more authorized miners;
4. lower fee;
5. name as a stable tie-breaker.

An entry is considered online when the source says the pool is running and its
status file is no more than 120 seconds old.
