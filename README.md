# knuth

Scope-enforced web application testing toolkit: logging proxy, repeater, positional fuzzer, crawler and scanner, all sharing one SQLite flow history. Python 3.10+, single dependency (`httpx`).

Use it only against systems you own or are explicitly authorised to test.

## Install

    pip install -e .          # or: pip install -e '.[dev]' for pytest
    python -m pytest          # runs against a bundled local vulnerable app

## Scope is mandatory

State lives in `.knuth/` (override with `--home`). An empty scope denies every request, and deny rules beat allow rules. Patterns are globs matched against `host` and `host:port`.

    knuth scope add '*.target.example' 10.0.0.5:8080
    knuth scope add admin.target.example --deny
    knuth scope check https://app.target.example/

Every outbound request from `repeat`, `fuzz` and `scan` is checked, and the proxy only records in-scope traffic (or blocks the rest with `--strict`).

## Commands

    knuth proxy --port 8080 [--strict] [--set-header 'X-Test: 1']
    knuth history [ID] [--host H] [--grep S] [--body]
    knuth repeat --id 12            # or: --raw request.txt --scheme http
    knuth fuzz req.txt -p sqli xss range:1-50 wordlist.txt --interesting
    knuth scan https://app.target.example/ --depth 2 [--active] -o report.md

The proxy forwards plain HTTP and records it. HTTPS is tunnelled via CONNECT and only the destination is logged (no TLS interception yet). Point a browser or `curl -x http://127.0.0.1:8080` at it.

### Fuzzing

Mark injection points in a raw request with section signs around the original value; every other position keeps its original value while one is varied (sniper mode).

    GET /item?id=§1§ HTTP/1.1
    Host: app.target.example

Builtin payload sets: `xss`, `sqli`, `lfi`, `ssti`, `special`; also `range:A-B` or a file. Results are flagged against the run's own statistics: `status` (non-modal), `length` (deviates from median beyond `--threshold`), `slow`, `reflected`, `err:<db>` (database/stack-trace signature), `vs-baseline`.

### Scanner

Passive checks run on every crawled response: CSP, clickjacking, nosniff, HSTS, Referrer-Policy, cookie flags, version banners, error and stack-trace disclosure, directory listings, wildcard CORS with credentials.

`--active` adds detection probes only: input reflection with metacharacter survival, a stray quote for database errors, a redirect target on `knuth.invalid`, a hostile `Origin`, and a few well-known exposed files (`/.git/HEAD`, `/.env`, ...). POST forms are probed only with `--active-post`. Findings are leads for manual verification, not proof of exploitability.

## Layout

    knuth/scope.py    scope rules and enforcement
    knuth/client.py   scope-checked async session (concurrency, delay, history logging)
    knuth/proxy.py    logging forward proxy
    knuth/fuzzer.py   positional fuzzer and anomaly flags
    knuth/checks.py   crawler, passive and active checks, report rendering
    knuth/store.py    SQLite history
    tests/            pytest suite and a deliberately vulnerable local target
