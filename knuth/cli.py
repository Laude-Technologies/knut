from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from . import __version__, checks, fuzzer
from .client import SendError, Session
from .models import parse_raw
from .proxy import ProxyServer
from .scope import OutOfScope, Scope
from .store import Store


def _headers(vals: list[str] | None) -> list[tuple[str, str]]:
    out = []
    for v in vals or []:
        k, _, val = v.partition(":")
        out.append((k.strip(), val.strip()))
    return out


def _ctx(a):
    home = Path(a.home)
    return Scope(home / "scope.json"), Store(home)


def _session(a, scope, store, source):
    return Session(scope, store, concurrency=a.concurrency, delay=a.delay, timeout=a.timeout,
                   verify=not a.insecure, source=source, extra_headers=_headers(a.header))


# ---------------------------------------------------------------- commands

def cmd_scope(a):
    scope = Scope(Path(a.home) / "scope.json")
    if a.action == "add":
        for p in a.patterns:
            scope.add(p, deny=a.deny)
    elif a.action == "rm":
        for p in a.patterns:
            if not scope.remove(p):
                print(f"not in scope file: {p}", file=sys.stderr)
    elif a.action == "check":
        rc = 0
        for u in a.patterns:
            ok = scope.check(u)
            print(f"{'IN ' if ok else 'OUT'} {u}")
            rc |= 0 if ok else 1
        return rc
    print(json.dumps({"allow": scope.allow, "deny": scope.deny}, indent=2))


def cmd_proxy(a):
    scope, store = _ctx(a)
    srv = ProxyServer(scope, store, strict=a.strict, set_headers=_headers(a.set_header),
                      verify=not a.insecure)
    print(f"knuth proxy on {a.listen}:{a.port} (strict={a.strict}); history in {a.home}/history.db")
    try:
        asyncio.run(srv.serve(a.listen, a.port))
    except KeyboardInterrupt:
        pass


def cmd_history(a):
    _, store = _ctx(a)
    if a.id is not None:
        req, resp = store.get(a.id)
        print(req.to_raw(), end="\n\n")
        if resp:
            print(f"HTTP {resp.status}  ({resp.elapsed*1000:.0f} ms)")
            print("\n".join(f"{k}: {v}" for k, v in resp.headers), end="\n\n")
            print(resp.text if a.body else f"[{len(resp.body)} bytes; use --body to print]")
        return
    for fid, ts, src, m, url, st, ln, el in store.list(a.limit, a.host, a.grep):
        print(f"{fid:>5} {time.strftime('%H:%M:%S', time.localtime(ts))} {src:<8} {m:<7} "
              f"{st if st is not None else '-':>3} {ln or 0:>8}  {url}")


def cmd_repeat(a):
    scope, store = _ctx(a)
    if a.id is not None:
        req, _ = store.get(a.id)
    else:
        req = parse_raw(Path(a.raw).read_text(), a.scheme)

    async def go():
        async with _session(a, scope, store, "repeater") as s:
            r = await s.send(req)
        print(f"HTTP {r.status}  ({r.elapsed*1000:.0f} ms, {len(r.body)} bytes)")
        print("\n".join(f"{k}: {v}" for k, v in r.headers), end="\n\n")
        print(r.text)

    asyncio.run(go())


def cmd_fuzz(a):
    scope, store = _ctx(a)
    template = Path(a.raw).read_text()
    payloads = []
    for spec in a.payloads:
        payloads += fuzzer.load_payloads(spec)

    async def go():
        async with _session(a, scope, store, "fuzzer") as s:
            base, results = await fuzzer.run(s, template, payloads, scheme=a.scheme,
                                             encode=a.urlencode, threshold=a.threshold)
        print(fuzzer.format_table(base, results, a.interesting))
        print(f"\n{len(results)} requests, {sum(1 for r in results if r.flags)} flagged")

    asyncio.run(go())


def cmd_scan(a):
    scope, store = _ctx(a)

    async def go():
        findings: list[checks.Finding] = []
        async with _session(a, scope, store, "scanner") as s:
            pages, endpoints = await checks.crawl(s, a.urls, a.depth, a.max_pages)
            for url, r in pages.items():
                findings += checks.passive(url, r)
            print(f"crawled {len(pages)} pages, {len(endpoints)} parameterised endpoints", file=sys.stderr)
            if a.active:
                findings += await checks.active(s, endpoints, list(pages)[:20], a.active_post)
                for u in a.urls:
                    findings += await checks.sensitive_paths(s, u)
        findings = checks.dedupe(findings)
        if a.format == "json":
            out = json.dumps([f.as_dict() for f in findings], indent=2)
        else:
            out = checks.to_markdown(findings, a.urls)
        if a.output:
            Path(a.output).write_text(out)
            print(f"{len(findings)} findings -> {a.output}", file=sys.stderr)
        else:
            print(out)

    asyncio.run(go())


# -------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="knuth", description="Scope-enforced web application testing toolkit.")
    p.add_argument("--version", action="version", version=f"knuth {__version__}")
    p.add_argument("--home", default=".knuth", help="state directory (scope.json, history.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def net(sp):
        sp.add_argument("-c", "--concurrency", type=int, default=10)
        sp.add_argument("--delay", type=float, default=0.0, help="seconds to wait before each request")
        sp.add_argument("--timeout", type=float, default=15.0)
        sp.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
        sp.add_argument("-H", "--header", action="append", help="extra header 'Name: value'")

    s = sub.add_parser("scope", help="manage authorised targets (empty scope denies everything)")
    s.add_argument("action", choices=["add", "rm", "list", "check"])
    s.add_argument("patterns", nargs="*", help="host globs (e.g. '*.example.com', '10.0.0.5:8080') or URLs for check")
    s.add_argument("--deny", action="store_true", help="with add: add an exclusion")
    s.set_defaults(fn=cmd_scope)

    s = sub.add_parser("proxy", help="logging HTTP proxy (CONNECT tunnelled, not decrypted)")
    s.add_argument("--listen", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--strict", action="store_true", help="block out-of-scope traffic instead of passing it unlogged")
    s.add_argument("--set-header", action="append", help="force a request header 'Name: value'")
    s.add_argument("-k", "--insecure", action="store_true")
    s.set_defaults(fn=cmd_proxy)

    s = sub.add_parser("history", help="list or show recorded flows")
    s.add_argument("id", nargs="?", type=int)
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--host")
    s.add_argument("--grep", help="substring in URL or response body")
    s.add_argument("--body", action="store_true", help="print response body when showing one flow")
    s.set_defaults(fn=cmd_history)

    s = sub.add_parser("repeat", help="resend a recorded flow or a raw request file")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--id", type=int)
    g.add_argument("--raw", help="raw request file")
    s.add_argument("--scheme", default="https")
    net(s)
    s.set_defaults(fn=cmd_repeat)

    s = sub.add_parser("fuzz", help="fuzz §marked§ positions in a raw request")
    s.add_argument("raw", help="raw request file containing §original§ markers")
    s.add_argument("-p", "--payloads", nargs="+", required=True,
                   help=f"wordlist file, range:1-100, or builtin: {', '.join(fuzzer.BUILTIN)}")
    s.add_argument("--scheme", default="https")
    s.add_argument("--urlencode", action="store_true", help="percent-encode payloads")
    s.add_argument("--threshold", type=float, default=0.10, help="relative length deviation to flag")
    s.add_argument("--interesting", action="store_true", help="only print flagged results")
    net(s)
    s.set_defaults(fn=cmd_fuzz)

    s = sub.add_parser("scan", help="crawl + passive checks (+ light active probes with --active)")
    s.add_argument("urls", nargs="+")
    s.add_argument("--depth", type=int, default=2)
    s.add_argument("--max-pages", type=int, default=100)
    s.add_argument("--active", action="store_true", help="send detection probes (reflection, quote, Origin, redirect)")
    s.add_argument("--active-post", action="store_true", help="also probe POST forms (may change state)")
    s.add_argument("--format", choices=["md", "json"], default="md")
    s.add_argument("-o", "--output")
    net(s)
    s.set_defaults(fn=cmd_scan)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a) or 0
    except OutOfScope as e:
        print(f"knuth: {e}", file=sys.stderr)
        return 2
    except (SendError, KeyError, ValueError, FileNotFoundError) as e:
        print(f"knuth: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
