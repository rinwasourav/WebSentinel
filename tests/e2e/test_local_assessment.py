from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from websentinel.cli import main


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"<html><title>Local fixture</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=fixture-secret; HttpOnly")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def test_end_to_end_local_lab_scan(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    port = server.server_address[1]
    try:
        code = main(
            [
                "assess",
                "--target",
                f"http://127.0.0.1:{port}/",
                "--scope",
                "127.0.0.1",
                "--authorized",
                "--local-lab",
                "--rate",
                "100",
                "--output",
                str(tmp_path / "reports"),
                "--database",
                str(tmp_path / "history.sqlite3"),
            ]
        )
        assert code == 0
        report_files = list((tmp_path / "reports").glob("*.json"))
        assert len(report_files) == 1
        report = json.loads(report_files[0].read_text())
        assert any(item["check_id"] == "headers.csp" for item in report["findings"])
        assert "fixture-secret" not in report_files[0].read_text()
        assert (tmp_path / "history.sqlite3").exists()
        assert main(["history", "--database", str(tmp_path / "history.sqlite3")]) == 0
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
