from dataclasses import dataclass
from urllib.parse import unquote

import pytest

from deny_path_fixtures import (
    assert_authenticated_allowed,
    assert_guest_unauthorized,
    assert_path_escape_rejected,
)


@dataclass(frozen=True)
class Response:
    status_code: int
    body: str = ""


class SecureDemoApp:
    """Small in-memory app used only to exercise the reusable assertions."""

    files = {"public/report.txt": "approved report"}

    def request(self, method, path, headers=None):
        headers = headers or {}
        if path == "/api/private":
            if headers.get("Authorization") != "Bearer fixture-user":
                return Response(401)
            return Response(200, "private data")

        if path.startswith("/files/"):
            requested = unquote(path.removeprefix("/files/"))
            if any(part == ".." for part in requested.split("/")):
                return Response(403)
            content = self.files.get(requested)
            return Response(200, content) if content else Response(404)

        return Response(404)


@pytest.fixture
def app():
    return SecureDemoApp()


def test_guest_is_rejected_from_protected_resource(app):
    assert_guest_unauthorized(app.request, "/api/private")


def test_authenticated_user_can_reach_protected_resource(app):
    assert_authenticated_allowed(
        app.request,
        "/api/private",
        authorization="Bearer fixture-user",
    )


def test_path_escape_is_rejected_without_reading_a_sibling(app):
    assert_path_escape_rejected(app.request, "/files/%2e%2e/private.txt")


def test_safe_file_path_is_allowed(app):
    response = app.request("GET", "/files/public/report.txt")
    assert response.status_code == 200
    assert response.body == "approved report"
