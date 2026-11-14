"""Logging forward proxy.

Plain-HTTP requests are forwarded and recorded (in-scope hosts only). HTTPS
CONNECT requests are tunnelled without decryption and only the destination is
recorded; TLS interception would need a locally trusted CA and is deliberately
not part of this version.
"""
from __future__ import annotations

import asyncio
import time

import httpx

from .models import HttpRequest, HttpResponse
from .scope import Scope
from .store import Store

HOP = {"connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding",
       "upgrade", "proxy-authorization", "proxy-authenticate"}


async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
    out = b""
    while True:
        size = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
        if size == 0:
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            return out
        out += await reader.readexactly(size)
        await reader.readline()


async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        w.close()


class ProxyServer:
    def __init__(self, scope: Scope, store: Store, *, strict: bool = False,
                 set_headers: list[tuple[str, str]] | None = None, verify: bool = True):
        self.scope, self.store, self.strict = scope, store, strict
        self.set_headers = set_headers or []
        self.client = httpx.AsyncClient(verify=verify, follow_redirects=False, timeout=30.0)

    async def serve(self, host: str, port: int) -> None:
        server = await asyncio.start_server(self._handle, host, port)
        async with server:
            await server.serve_forever()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            if not line.strip():
                return
            method, target, _ = line.decode("latin1").rstrip().split(" ", 2)
            headers: list[tuple[str, str]] = []
            while True:
                h = await reader.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
                k, _, v = h.decode("latin1").partition(":")
                headers.append((k.strip(), v.strip()))
            if method == "CONNECT":
                await self._tunnel(target, reader, writer)
            else:
                await self._forward(method, target, headers, reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError, ValueError):
            pass
        finally:
            writer.close()

    async def _tunnel(self, target: str, reader, writer) -> None:
        host, _, port = target.partition(":")
        url = f"https://{host}:{port or 443}/"
        if self.strict and not self.scope.check(url):
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return
        try:
            ur, uw = await asyncio.open_connection(host, int(port or 443))
        except OSError:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return
        if self.scope.check(url):
            self.store.add(HttpRequest("CONNECT", url), None, "proxy")
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(_pipe(reader, uw), _pipe(ur, writer))

    async def _forward(self, method, target, headers, reader, writer) -> None:
        if not target.startswith("http://"):
            msg = b"knuth proxy: send absolute-form requests (configure this as an HTTP proxy)\n"
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\n\r\n" % len(msg) + msg)
            await writer.drain()
            return
        hmap = {k.lower(): v for k, v in headers}
        body = b""
        if "chunked" in hmap.get("transfer-encoding", "").lower():
            body = await _read_chunked(reader)
        elif hmap.get("content-length", "").isdigit():
            body = await reader.readexactly(int(hmap["content-length"]))
        in_scope = self.scope.check(target)
        if self.strict and not in_scope:
            msg = b"knuth proxy: target out of scope\n"
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\n" % len(msg) + msg)
            await writer.drain()
            return
        out_headers = [(k, v) for k, v in headers
                       if k.lower() not in HOP and k.lower() != "content-length"]
        for name, value in self.set_headers:
            out_headers = [(k, v) for k, v in out_headers if k.lower() != name.lower()]
            out_headers.append((name, value))
        req = HttpRequest(method, target, out_headers, body)
        start = time.perf_counter()
        try:
            r = await self.client.request(method, target, headers=out_headers, content=body or None)
        except httpx.HTTPError as e:
            msg = f"knuth proxy: upstream error: {e}\n".encode()
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\n\r\n" % len(msg) + msg)
            await writer.drain()
            return
        resp = HttpResponse(r.status_code, list(r.headers.multi_items()), r.content,
                            time.perf_counter() - start)
        if in_scope:
            self.store.add(req, resp, "proxy")
        skip = HOP | {"content-encoding", "content-length"}
        head = f"HTTP/1.1 {resp.status} {r.reason_phrase}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in resp.headers if k.lower() not in skip)
        head += f"Content-Length: {len(resp.body)}\r\nConnection: close\r\n\r\n"
        writer.write(head.encode("latin1", "replace") + resp.body)
        await writer.drain()
