"""Scope-enforcing async HTTP session used by every active module."""
from __future__ import annotations

import asyncio
import time

import httpx

from .models import HttpRequest, HttpResponse
from .scope import Scope
from .store import Store


class SendError(Exception):
    pass


class Session:
    def __init__(self, scope: Scope, store: Store | None = None, *, concurrency: int = 10,
                 delay: float = 0.0, timeout: float = 15.0, verify: bool = True,
                 source: str = "session", extra_headers: list[tuple[str, str]] | None = None):
        self.scope = scope
        self.store = store
        self.delay = delay
        self.source = source
        self.extra_headers = extra_headers or []
        self._timeout = timeout
        self._verify = verify
        self._conc = concurrency
        self.client: httpx.AsyncClient | None = None
        self._sem: asyncio.Semaphore | None = None

    async def __aenter__(self) -> "Session":
        self.client = httpx.AsyncClient(verify=self._verify, timeout=self._timeout,
                                        follow_redirects=False)
        self._sem = asyncio.Semaphore(self._conc)
        return self

    async def __aexit__(self, *exc) -> None:
        assert self.client
        await self.client.aclose()

    async def send(self, req: HttpRequest) -> HttpResponse:
        assert self.client and self._sem
        self.scope.require(req.url)
        headers = [(k, v) for k, v in req.headers if k.lower() != "content-length"]
        have = {k.lower() for k, _ in headers}
        headers += [(k, v) for k, v in self.extra_headers if k.lower() not in have]
        async with self._sem:
            if self.delay:
                await asyncio.sleep(self.delay)
            start = time.perf_counter()
            try:
                r = await self.client.request(req.method, req.url, headers=headers,
                                              content=req.body or None)
            except httpx.HTTPError as e:
                raise SendError(f"{type(e).__name__}: {e}") from e
            elapsed = time.perf_counter() - start
        resp = HttpResponse(r.status_code, list(r.headers.multi_items()), r.content, elapsed)
        if self.store:
            self.store.add(req, resp, self.source)
        return resp
