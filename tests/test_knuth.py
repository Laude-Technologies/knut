import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent))
import vulnapp  # noqa: E402

from knuth import checks, fuzzer  # noqa: E402
from knuth.cli import main  # noqa: E402
from knuth.client import Session  # noqa: E402
from knuth.models import HttpRequest  # noqa: E402
from knuth.proxy import ProxyServer  # noqa: E402
from knuth.scope import OutOfScope, Scope  # noqa: E402
from knuth.store import Store  # noqa: E402


@pytest.fixture()
def target(tmp_path):
    srv, port = vulnapp.start()
    yield tmp_path, f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_scope_semantics(tmp_path):
    s = Scope(tmp_path / "scope.json")
    assert not s.check("http://127.0.0.1/")  # empty denies all
    s.add("*.example.com")
    s.add("admin.example.com", deny=True)
    s.add("10.0.0.5:8080")
    assert s.check("https://app.example.com/x")
    assert not s.check("https://admin.example.com/")
    assert s.check("http://10.0.0.5:8080/") and not s.check("http://10.0.0.5:9090/")
    assert not s.check("https://example.org/")
    assert Scope(tmp_path / "scope.json").allow == s.allow  # persisted


def test_out_of_scope_blocked(target):
    home, base = target
    scope = Scope(home / "scope.json")

    async def go():
        async with Session(scope) as s:
            await s.send(HttpRequest("GET", base + "/"))

    with pytest.raises(OutOfScope):
        asyncio.run(go())


def test_scan_finds_planted_issues(target):
    home, base = target
    scope = Scope(home / "scope.json")
    scope.add("127.0.0.1")
    store = Store(home)

    async def go():
        async with Session(scope, store, source="scanner") as s:
            pages, eps = await checks.crawl(s, [base + "/"])
            f = []
            for u, r in pages.items():
                f += checks.passive(u, r)
            f += await checks.active(s, eps, list(pages))
            f += await checks.sensitive_paths(s, base)
            return checks.dedupe(f)

    found = {f.check for f in asyncio.run(go())}
    assert {"reflected-xss", "sqli-error", "open-redirect", "exposed-file",
            "cookie-flags", "missing-csp", "cors-reflected-origin"} <= found


def test_fuzzer_flags_anomalies(target):
    home, base = target
    scope = Scope(home / "scope.json")
    scope.add("127.0.0.1")
    host = base.removeprefix("http://")
    tpl = f"GET /item?id=§1§ HTTP/1.1\nHost: {host}\n\n"

    async def go():
        async with Session(scope) as s:
            return await fuzzer.run(s, tpl, fuzzer.load_payloads("sqli"), scheme="http")

    base_r, results = asyncio.run(go())
    assert base_r.status == 200
    quote = next(r for r in results if r.payload == "'")
    assert quote.status == 500 and any(f.startswith("err:mysql") for f in quote.flags)


def test_marker_render():
    t = "a=§1§&b=§2§"
    assert fuzzer.positions(t) == ["1", "2"]
    assert fuzzer.render(t, 1, "X") == "a=1&b=X"
    assert fuzzer.render(t, 0, None) == "a=1&b=2"


def test_proxy_logs_in_scope_only(target):
    home, base = target
    scope = Scope(home / "scope.json")
    scope.add("127.0.0.1")
    store = Store(home)

    async def go():
        srv = ProxyServer(scope, store)
        server = await asyncio.start_server(srv._handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}") as c:
            r = await c.get(base + "/search?q=hello")
        server.close()
        return r

    r = asyncio.run(go())
    assert r.status_code == 200 and "results for hello" in r.text
    rows = store.list()
    assert len(rows) == 1 and rows[0][2] == "proxy"


def test_scan_refuses_empty_scope(target):
    home, base = target
    assert main(["--home", str(home / "empty"), "scan", base + "/"]) == 2


def test_cli_roundtrip(target, capsys):
    home, base = target
    h = str(home / "st")
    assert main(["--home", h, "scope", "add", "127.0.0.1"]) == 0
    assert main(["--home", h, "scope", "check", base + "/"]) == 0
    assert main(["--home", h, "scan", base + "/", "--active", "--format", "json", "-o", str(home / "r.json")]) == 0
    data = json.loads((home / "r.json").read_text())
    assert any(f["check"] == "sqli-error" for f in data)
    assert main(["--home", h, "history", "--limit", "5"]) == 0
    assert main(["--home", str(home / "other"), "repeat", "--raw", str(home / "nope")]) == 1
