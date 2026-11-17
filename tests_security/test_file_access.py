"""Selected vulnerability 2 - path traversal in GET /files (finding F08).

Requirements: R6 (only files inside the materials directory may be read),
R1 (downloads require authentication), R7 (client errors without internal
paths or exception details).

Every test uses a temporary materials directory and a sentinel file outside
it, so no real operating-system or application file is ever read.
"""

import pytest

import baseline_secure_coding_api as api

SECRET = "TOP-SECRET-OUTSIDE-MATERIALS"
DENIED = (400, 403, 404)


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


@pytest.fixture
def materials(tmp_path, monkeypatch):
    """Layout:
        tmp/materials/notes.txt                (allowed)
        tmp/materials/week1/slides.txt         (allowed, nested)
        tmp/secret.txt                         (outside)
        tmp/materials-private/secret.txt       (outside, shares name prefix)
    """
    materials_dir = tmp_path / "materials"
    (materials_dir / "week1").mkdir(parents=True)
    (materials_dir / "notes.txt").write_text("allowed teaching material", encoding="utf-8")
    (materials_dir / "week1" / "slides.txt").write_text("week 1 slides", encoding="utf-8")

    outside = tmp_path / "secret.txt"
    outside.write_text(SECRET, encoding="utf-8")
    sibling = tmp_path / "materials-private"
    sibling.mkdir()
    (sibling / "secret.txt").write_text(SECRET, encoding="utf-8")

    monkeypatch.setattr(api, "MATERIALS_DIR", materials_dir)
    return {"dir": materials_dir, "outside": outside, "sibling": sibling / "secret.txt"}


def assert_not_disclosed(response):
    assert response.status_code in DENIED
    assert SECRET.encode() not in response.data


# --- Legitimate operations that must keep working ---------------------------

def test_authenticated_user_can_download_material(client, materials):
    login(client, "alice", "alicepw")

    response = client.get("/files", query_string={"path": "notes.txt"})

    assert response.status_code == 200
    assert response.data == b"allowed teaching material"


def test_authenticated_user_can_download_nested_material(client, materials):
    login(client, "prof_srs", "profpw")

    response = client.get("/files", query_string={"path": "week1/slides.txt"})

    assert response.status_code == 200
    assert response.data == b"week 1 slides"


# --- Malicious requests -----------------------------------------------------

def test_parent_directory_traversal_is_blocked(client, materials):
    login(client, "alice", "alicepw")

    response = client.get("/files", query_string={"path": "../secret.txt"})

    assert_not_disclosed(response)


def test_traversal_hidden_after_valid_subdirectory_is_blocked(client, materials):
    """Variation: starts inside the directory, so a 'path starts with a
    valid folder' or 'no leading ..' check would accept it."""
    login(client, "alice", "alicepw")

    response = client.get("/files", query_string={"path": "week1/../../secret.txt"})

    assert_not_disclosed(response)


def test_absolute_path_is_blocked(client, materials):
    """Variation: pathlib discards MATERIALS_DIR when the right operand is
    absolute, so filtering only '..' does not help."""
    login(client, "alice", "alicepw")

    response = client.get("/files", query_string={"path": str(materials["outside"])})

    assert_not_disclosed(response)


def test_sibling_directory_with_same_prefix_is_blocked(client, materials):
    """Variation: defeats a containment check written as
    str(target).startswith(str(MATERIALS_DIR))."""
    login(client, "alice", "alicepw")

    response = client.get(
        "/files", query_string={"path": "../materials-private/secret.txt"}
    )

    assert_not_disclosed(response)


def test_percent_encoded_traversal_is_blocked(client, materials):
    """Variation: the raw query string carries an encoded '../'."""
    login(client, "alice", "alicepw")

    response = client.get("/files?path=%2e%2e%2fsecret.txt")

    assert_not_disclosed(response)


def test_unauthenticated_download_is_rejected(client, materials):
    response = client.get("/files", query_string={"path": "notes.txt"})

    assert response.status_code == 401
    assert b"allowed teaching material" not in response.data


def test_missing_material_returns_client_error_without_internal_path(client, materials):
    login(client, "alice", "alicepw")

    response = client.get("/files", query_string={"path": "missing.txt"})

    assert response.status_code == 404
    body = response.get_data(as_text=True)
    assert str(materials["dir"]) not in body
    assert "FileNotFoundError" not in body
    assert "Traceback" not in body
