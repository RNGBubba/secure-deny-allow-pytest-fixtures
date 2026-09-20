"""Reusable pytest assertions for secure guest and path handling."""


def assert_guest_unauthorized(request, path):
    response = request("GET", path)
    assert response.status_code == 401, (
        f"guest request to {path!r} must return 401, "
        f"got {response.status_code}"
    )


def assert_authenticated_allowed(request, path, *, authorization):
    response = request("GET", path, {"Authorization": authorization})
    assert response.status_code == 200, (
        f"authenticated request to {path!r} must return 200, "
        f"got {response.status_code}"
    )


def assert_path_escape_rejected(request, path):
    response = request("GET", path)
    assert response.status_code in {400, 403, 404}, (
        f"path escape {path!r} must be rejected, got {response.status_code}"
    )
