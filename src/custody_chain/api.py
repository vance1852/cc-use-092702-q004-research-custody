"""无第三方依赖的科研采样许可与保管链 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .errors import CustodyChainError, ValidationFailed
from .service import CustodyChainService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class JsonApplication:
    def __init__(self, service: CustodyChainService) -> None:
        self.service = service

    @staticmethod
    def _actor(headers: Mapping[str, str]) -> str:
        actor = headers.get("x-actor-id", "").strip()
        if not actor:
            raise ValidationFailed("缺少 X-Actor-Id")
        return actor

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailed("请求体必须是 UTF-8 JSON 对象") from exc
        if not isinstance(value, dict):
            raise ValidationFailed("请求体必须是 JSON 对象")
        return value

    def handle(self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b"") -> Response:
        normalized = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}
            if method == "POST" and path == "/users":
                return Response(201, self.service.create_user(
                    payload["user_id"], payload["display_name"], payload["role"], payload["org"]))
            actor = self._actor(normalized)
            # 许可
            if method == "POST" and path == "/permits":
                return Response(201, self.service.grant_permit(actor, payload))
            if method == "POST" and len(parts) == 2 and parts[0] == "permits" and parts[1] == "revise":
                return Response(200, self.service.revise_permit(actor, payload))
            if method == "POST" and len(parts) == 3 and parts[0] == "permits" and parts[2] == "revoke":
                return Response(200, self.service.revoke_permit(
                    actor, parts[1], int(payload["expected_version"]), payload["reason"]))
            if method == "GET" and len(parts) == 2 and parts[0] == "permits":
                return Response(200, self.service.permit_status(actor, parts[1]))
            # 样本与保管操作
            if method == "POST" and path == "/samples":
                return Response(201, self.service.collect_sample(actor, payload))
            if method == "GET" and len(parts) == 2 and parts[0] == "samples":
                return Response(200, self.service.sample_status(actor, parts[1]))
            if method == "GET" and len(parts) == 3 and parts[0] == "samples" and parts[2] == "chain":
                return Response(200, self.service.sample_chain(actor, parts[1]))
            if method == "POST" and path == "/samples/split":
                return Response(201, self.service.apply_operation(actor, "split", payload))
            if method == "POST" and path == "/samples/merge":
                return Response(201, self.service.apply_operation(actor, "merge", payload))
            if method == "POST" and path == "/samples/destroy":
                return Response(201, self.service.apply_operation(actor, "destroy", payload))
            # 跨机构交接
            if method == "POST" and path == "/transfers":
                return Response(201, self.service.propose_transfer(actor, payload))
            if method == "POST" and len(parts) == 3 and parts[0] == "transfers" and parts[2] == "confirm":
                return Response(200, self.service.confirm_transfer(
                    actor, parts[1], payload["receiving_custodian_id"], payload["receiving_seal_digest"]))
            if method == "POST" and len(parts) == 3 and parts[0] == "transfers" and parts[2] == "reject":
                return Response(200, self.service.reject_transfer(actor, parts[1], payload["reason"]))
            # 核对
            if method == "GET" and path == "/transfers/missing":
                return Response(200, self.service.missing_handovers(actor))
            if method == "GET" and path == "/audit/chain":
                return Response(200, self.service.audit_chain(actor))
            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except CustodyChainError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def make_handler(application: JsonApplication):
    import threading

    dispatch_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "CustodyChain/1"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            # SQLite 连接跨线程共享，用锁把每个请求的事务串行化。
            with dispatch_lock:
                response = application.handle(self.command, self.path, dict(self.headers.items()), body)
            encoded = json.dumps(response.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动科研采样许可与保管链服务")
    parser.add_argument("--database", type=Path, default=Path("custody_chain.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args(argv)
    connection = connect(args.database, check_same_thread=False)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(JsonApplication(CustodyChainService(connection))))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
