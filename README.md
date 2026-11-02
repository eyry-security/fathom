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

DNS defaults follow the aiodnsbrute/c-ares model: 128 concurrent candidates
(a hard closed-loop window), a 2s timeout and 2 retries (3 tries) **per record
type**, A + AAAA record types, and no rate cap or circuit breaker by default.
`--dns-timeout` changes the per-type timeout, `--retries` changes the per-type
retry budget, and `--timeout` is only an engine-level backstop.
`--rate` optionally adds a global lookups/sec cap; `--cname` adds CNAME to the
query set. `--resolver` accepts an IP or `IP:PORT`, repeatable or
comma-separated; explicit resolvers are round-robin rotated per attempt. With
no `--resolver`, hickory-dns reads the system resolver config.

Each record type is resolved independently with its own 2s try, so a
successful A answer is kept even if AAAA times out; timed-out types are listed
in `dns.incomplete_types` and counted in `dns.type_stats`. NXDOMAIN and NODATA
are ordinary negative answers (filtered, not errors). SERVFAIL/REFUSED are
retried up to the per-type budget and counted in `dns.rcodes`; a candidate only
counts as an engine error when every requested record type failed. The stats
trailer gains an additive `dns` object with per-type
`attempts`/`timeouts`/`incomplete` totals and the rcode distribution.

To avoid doubling resolver load on the common negative case, the first type
(A, or the first configured type) gets a short head start. A fast authoritative
NXDOMAIN cancels the remaining types because a non-existent name cannot have
AAAA/CNAME data; any other outcome (answer, NODATA, timeout) still queries
every configured type. AAAA/CNAME are therefore still collected for every name
that exists, and `per_type` attempt counts reflect queries actually started.

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
{"type":"result","input":{"FUZZ":"www"},"dns":{"host":"www.example.com","domain":"example.com","record_types":["A","AAAA"],"rcode":"NOERROR","wildcard":false,"answers":[{"type":"A","value":"192.0.2.10","ttl":300},{"type":"AAAA","value":"2001:db8::10","ttl":300}],"type_stats":[{"type":"A","attempts":1,"timeouts":0,"incomplete":0,"rcode":"NOERROR"},{"type":"AAAA","attempts":1,"timeouts":0,"incomplete":0,"rcode":"NOERROR"}],"rcodes":{"NOERROR":2},"incomplete_types":[]},"status":0,"size":42,"words":6,"lines":2,"duration_ms":3}
{"type":"stats","requests":100,"errors":0,"kept":4,"filtered":96,"elapsed_ms":812,"rps":123.15,"dns":{"per_type":{"A":{"attempts":100,"timeouts":0,"incomplete":0},"AAAA":{"attempts":100,"timeouts":0,"incomplete":0}},"rcodes":{"NXDOMAIN":96,"NOERROR":4}}}
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

## resolver-bench

The repo also builds `resolver-bench` (`src/bin/resolver-bench.rs`), a standalone
DNS resolver vetting tool. Point it at a truth file of hosts that must resolve;
it grades each resolver on correctness, latency, and error growth under load:

- **Correctness** — every truth host must resolve, and generated
  `nx<random>.<domain>` labels must not. A missing host and an invented answer
  both count as wrong; an invented answer sets the wildcard flag.
- **Latency** — A-query median and p95 at low concurrency.
- **Error growth** — a sustained burst through a closed Fathom-like concurrency
  window, reported as an overall error rate and in 10 time buckets. Late growth
  past the early rate marks the resolver `DEGRADED`.

A resolver that returns any wrong answer, or exceeds a 5% burst error rate,
gets a `FAIL` verdict. Reports are ranked by wrong answers, then burst error
rate, then p95. Every built-in and custom resolver carries an operator name.

`--truth` is required. `--domains` defaults to `example.com,eyry.io`,
`--concurrency` to 256, `--burst` to 2000, and `--queries` to 50. Without
`--resolvers`, it uses a built-in set of public resolvers.

```sh
# truth.txt: one host per line that must resolve
$ cat truth.txt
example.com
www.example.com

# Built-in resolvers, one probe domain
$ cargo run --bin resolver-bench -- --truth truth.txt --domains example.com

# Explicit resolvers (`name,ip` per line) and a JSON report
$ cat resolvers.txt
Cloudflare,1.1.1.1
Google,8.8.8.8

$ cargo run --bin resolver-bench -- \
    --truth truth.txt --domains example.com \
    --resolvers resolvers.txt --json report.json
```

`--timeout` accepts values like `1s` or `500ms`; `--json` writes the full
per-resolver metrics: correctness, latency, burst buckets, and verdict.

## The DNS trio

Magpie builds per-target lists from a target's own site and hands them to
Fathom. Fathom's tiered lists merge 10 public corpora, ranked by cross-corpus
frequency at 10k / 50k / ~500k practical cuts. On a large public bug bounty
program, the 50k tier found 30 more verified hosts than the standard bitquark
top-100k baseline; the 500k cut found 91 more. Every claimed host was
independently verified: 100% precision across all benchmark runs.
`resolver-bench` vets the resolvers; Fathom runs the list.

Magpie: https://github.com/eyry-security/magpie
