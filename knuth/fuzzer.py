"""Positional fuzzer with anomaly detection.

Mark injection points in a raw request with section signs: `GET /item?id=§1§`.
The text between the markers is the original value (used for the baseline and for
every position that is not currently being fuzzed - "sniper" mode).
"""
from __future__ import annotations

import asyncio
import re
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from .checks import ERROR_SIGNATURES
from .client import SendError, Session
from .models import HttpRequest, parse_raw

MARK = re.compile("§(.*?)§", re.S)

BUILTIN = {
    "xss": ['<script>knuth(1)</script>', '"><img src=x onerror=knuth(1)>', "'-knuth(1)-'",
            "javascript:knuth(1)", "<svg/onload=knuth(1)>"],
    "sqli": ["'", '"', "' OR '1'='1", "' OR 1=1-- -", "1 AND 1=1", "1 AND 1=2", "') OR ('1'='1",
             "';--", "1' ORDER BY 100-- -"],
    "lfi": ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd", "/etc/passwd", "php://filter/convert.base64-encode/resource=index"],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}"],
    "special": ["", " ", "null", "undefined", "-1", "0", "99999999999", "%00", "%0d%0aX-Knuth: 1",
                "A" * 1024, "[]", "{}", "true", "false"],
}


def positions(template: str) -> list[str]:
    return MARK.findall(template)


def render(template: str, index: int, payload: str | None) -> str:
    """Fill position `index` with payload; every other position keeps its original value."""
    n = -1

    def sub(m: re.Match) -> str:
        nonlocal n
        n += 1
        return payload if (n == index and payload is not None) else m.group(1)

    return MARK.sub(sub, template)


def load_payloads(spec: str) -> list[str]:
    if spec in BUILTIN:
        return list(BUILTIN[spec])
    if spec.startswith("range:"):
        lo, _, hi = spec[6:].partition("-")
        return [str(i) for i in range(int(lo), int(hi) + 1)]
    return [l for l in Path(spec).read_text(errors="replace").splitlines() if l != ""]


@dataclass
class Result:
    index: int
    payload: str
    status: int = 0
    length: int = 0
    elapsed: float = 0.0
    error: str = ""
    flags: list[str] = field(default_factory=list)


def _build(template: str, index: int, payload: str | None, scheme: str, encode: bool) -> HttpRequest:
    if payload is not None and encode:
        payload = quote(payload, safe="")
    return parse_raw(render(template, index, payload), scheme)


async def run(session: Session, template: str, payloads: list[str], *, scheme: str = "https",
              encode: bool = False, threshold: float = 0.10):
    """Returns (baseline Result, [Result]) with anomaly flags filled in."""
    npos = len(positions(template))
    if npos == 0:
        raise ValueError("no §markers§ found in the request template")

    async def one(index: int, payload: str | None) -> Result:
        res = Result(index, "<baseline>" if payload is None else payload)
        try:
            req = _build(template, index, payload, scheme, encode)
            r = await session.send(req)
        except SendError as e:
            res.error = str(e)
            res.flags.append("error")
            return res
        res.status, res.length, res.elapsed = r.status, len(r.body), r.elapsed
        text = r.text
        if payload and len(payload) >= 4 and payload in text:
            res.flags.append("reflected")
        for name, rx in ERROR_SIGNATURES:
            if rx.search(text):
                res.flags.append(f"err:{name}")
                break
        return res

    base = await one(0, None)
    jobs = [one(i, p) for i in range(npos) for p in payloads]
    results = await asyncio.gather(*jobs)

    # Anomalies are measured against the unmodified baseline request, so a payload is
    # flagged because it changed the server's behaviour, not because most payloads did.
    ok = [r for r in results if not r.error]
    if ok and not base.error:
        med_t = statistics.median(r.elapsed for r in ok)
        for r in ok:
            if r.status != base.status:
                r.flags.append("status")
            if base.length:
                if abs(r.length - base.length) / base.length > threshold:
                    r.flags.append("length")
            elif r.length:
                r.flags.append("length")
            if r.elapsed > max(med_t, base.elapsed) * 3 + 0.5:
                r.flags.append("slow")
    return base, results


def format_table(base: Result, results: list[Result], only_interesting: bool = False) -> str:
    rows = [r for r in results if r.flags] if only_interesting else results
    out = [f"baseline: status={base.status} len={base.length} t={base.elapsed*1000:.0f}ms",
           f"{'pos':>3} {'status':>6} {'len':>8} {'ms':>6}  {'payload':<40} flags"]
    for r in rows:
        shown = r.payload.replace("\n", "\\n")
        shown = shown if len(shown) <= 40 else shown[:37] + "..."
        out.append(f"{r.index:>3} {r.status:>6} {r.length:>8} {r.elapsed*1000:>6.0f}  {shown:<40} "
                   f"{','.join(r.flags)}{' ' + r.error if r.error else ''}")
    return "\n".join(out)
