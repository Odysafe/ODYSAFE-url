from __future__ import annotations

import functools
import http.server


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/redirect302":
            self.send_response(302)
            self.send_header("Location", "/target.html")
            self.end_headers()
            return
        if self.path == "/redirect-external":
            self.send_response(302)
            self.send_header("Location", "http://192.0.2.1/blocked")
            self.end_headers()
            return
        if self.path == "/secondary-external.html":
            body = b'<html><title>Blocked secondary</title><img src="http://192.0.2.1/a.png"></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def log_message(self, format: str, *args: object) -> None:
        return


server = http.server.ThreadingHTTPServer(("0.0.0.0", 8000),
                                         functools.partial(Handler, directory="/srv/fixtures"))
server.serve_forever()
