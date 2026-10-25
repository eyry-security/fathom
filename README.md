# fathom — Rust fuzzer + DNS brute-forcer for the Eyry suite (one engine, two modes).

`fathom` is one transport-agnostic scheduler (`wordlist`, `engine`, `calibration`,
`matcher`, `output`) with two targets:

- **http** — fuzz an HTTP template containing `FUZZ` / `FUZZ2`.
- **dns** — brute-force `<word>.<domain>` with wildcard filtering and a
  Vedette-compatible host handoff.

## HTTP mode

```sh
fathom http -u 'https://example.com/FUZZ' -w words.txt
```

## DNS mode

```sh
# System resolver, A + AAAA, 3 wildcard probes, human output
fathom dns -d example.com -w subs.txt

# Explicit resolvers (rotated per lookup), CNAME answers, JSONL to a file
fathom dns -d example.com -w subs.txt \
  --resolver 1.1.1.1,9.9.9.9 --cname -o dns.jsonl --format jsonl

# Show wildcard answers too (tagged `wildcard: true`)
fathom dns -d example.com -w subs.txt --show-wildcards

# Handoff to Vedette (one plain host per line on stdout)
fathom dns -d example.com -w subs.txt --emit-hosts | vedette
```

DNS defaults are separate from HTTP: 2000 lookups/sec cap, 5s per-lookup
timeout, 128 concurrent lookups, A + AAAA record types. `--rate` overrides the
cap; `--cname` adds CNAME to the query set. `--resolver` accepts an IP or
`IP:PORT`, repeatable or comma-separated; explicit resolvers are round-robin
rotated. With no `--resolver`, hickory-dns reads the system resolver config.
The same engine supplies retries, circuit breaking and per-lookup timeouts.

### Wildcard filtering

Before the run, `--wildcard-probes N` (default 3, 0 disables) resolves
`<random-label>.<domain>` at the exact level being brute-forced. All returned
answer identities (`record type`, `value`) are unioned into a wildcard set;
TTL is not part of the identity. During the run:

- a result with an empty answer set (NXDOMAIN / NODATA) is filtered;
- a non-empty answer set that is a **subset of or equal to** the wildcard set
  is filtered;
- a result with any additional/distinct record is kept;
- `--show-wildcards` keeps wildcard results and tags the payload
  `"wildcard": true`.

Wildcard probes use the same scheduler/rate cap but are not counted in the run
statistics.

### JSONL delta (stage 1 envelope extended with a `dns` payload)

The envelope is unchanged: one `result` object per kept lookup and exactly one
`stats` trailer. DNS results add a nested `dns` object and use the DNS RCODE as
the numeric `status` (0 = NOERROR, 3 = NXDOMAIN, ...). `size`, `words` and
`lines` are derived from the textual answer body, so the existing matcher
fields remain meaningful. `input.FUZZ` is the wordlist label.

```json
{"type":"result","input":{"FUZZ":"www"},"dns":{"host":"www.example.com","domain":"example.com","record_types":["A","AAAA"],"rcode":"NOERROR","wildcard":false,"answers":[{"type":"A","value":"192.0.2.10","ttl":300},{"type":"AAAA","value":"2001:db8::10","ttl":300}]},"status":0,"size":42,"words":6,"lines":2,"duration_ms":3}
{"type":"stats","requests":100,"errors":0,"kept":4,"filtered":96,"elapsed_ms":812,"rps":123.15}
```

`dns.answers` is sorted by type then value and de-duplicated; each answer
carries its own TTL.

### Vedette handoff format

`--emit-hosts` writes exactly one line per kept host to stdout, in the format
Vedette accepts from stdin/files: a bare `host` (or `host:port` when
`--emit-port` is supplied). It never emits headings, URLs, JSON, or stats on
stdout, so `fathom dns ... --emit-hosts | vedette` works directly. The stats
summary goes to stderr in this mode.

```sh
$ fathom dns -d example.com -w subs.txt --emit-hosts --emit-port 8443
www.example.com:8443
api.example.com:8443
```
