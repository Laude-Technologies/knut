"""Deliberately vulnerable local target for knuth's own tests. Binds to 127.0.0.1 only."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=()):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        if u.path == "/":
            self._send(200, '<title>home</title><a href="/search?q=x">search</a> <a href="/item?id=1">item</a>'
                            ' <a href="/go?next=/">go</a> <a href="/api">api</a> <form action="/login" method="post">'
                            '<input name="user"><input name="pw"></form>',
                       extra=[("Server", "vulnapp/1.0"), ("Set-Cookie", "sessionid=abc123; Path=/")])
        elif u.path == "/search":
            self._send(200, f"<html>results for {q.get('q', '')}</html>")  # unescaped reflection
        elif u.path == "/item":
            i = q.get("id", "")
            if "'" in i:
                self._send(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server")
            else:
                self._send(200, f"<html>item {i}" + ("A" * (50 if i == "1" else 10)) + "</html>")
        elif u.path == "/go":
            self._send(302, "", extra=[("Location", q.get("next", "/"))])
        elif u.path == "/.env":
            self._send(200, "DB_PASSWORD=hunter2\nSECRET_KEY=x", "text/plain")
        elif u.path == "/api":
            o = self.headers.get("Origin", "")
            self._send(200, "{}", "application/json",
                       extra=[("Access-Control-Allow-Origin", o), ("Access-Control-Allow-Credentials", "true")])
        else:
            self._send(404, "nope")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        self._send(200, "ok")


def start() -> tuple[ThreadingHTTPServer, int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]
