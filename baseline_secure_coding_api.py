import dataclasses
import pathlib
import typing

import flask

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"

# -----------------------------------------------------------------------------
# Intentionally small in-memory "database"
# -----------------------------------------------------------------------------

BASE_DIR = pathlib.Path(__file__).resolve().parent
MATERIALS_DIR = BASE_DIR / "materials"
MATERIALS_DIR.mkdir(exist_ok=True)

# Seed a couple of demo files.
(MATERIALS_DIR / "srs-summary.txt").write_text(
    "Secure Requirements Engineering summary", encoding="utf-8"
)
(MATERIALS_DIR / "secure-coding.txt").write_text(
    "Secure coding practices notes", encoding="utf-8"
)


@dataclasses.dataclass
class User:
    username: str
    password: str
    role: str
    student_id: typing.Optional[int] = None
    courses: typing.Optional[list[str]] = None


USERS = {
    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),
    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),
    "prof_srs": User(
        username="prof_srs", password="profpw", role="professor", courses=["SRS"]
    ),
    "admin1": User(username="admin1", password="adminpw", role="admin"),
}

STUDENT_PROFILES = {
    1001: {"student_id": 1001, "name": "Alice", "email": "alice@uc.pt", "program": "MEI"},
    1002: {"student_id": 1002, "name": "Bob", "email": "bob@uc.pt", "program": "MEI"},
}

GRADES = [
    {"student_id": 1001, "course_id": "SRS", "grade": 14},
    {"student_id": 1002, "course_id": "SRS", "grade": 15},
    {"student_id": 1001, "course_id": "SSD", "grade": 16},
]

def find_grade(student_id, course_id):
    for row in GRADES:
        if row["student_id"] == student_id and row["course_id"] == course_id:
            return row
    return None


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def index():
    return {
        "message": "Baseline Secure Coding API",
        "endpoints": [
            "POST /login",
            "POST /logout",
            "GET /me",
            "GET /students/<student_id>/profile",
            "POST /grades/update",
            "GET /grades/<student_id>",
            "GET /files?path=<name>",
        ],
    }

@app.post("/login")
def login():
    username = flask.request.form.get("username", "")
    password = flask.request.form.get("password", "")

    user = USERS.get(username)
    if user is None or user.password != password:
        return {"error": "invalid credentials"}, 401

    flask.session["user"] = user.username
    flask.session["role"] = user.role
    flask.session["student_id"] = user.student_id
    flask.session["courses"] = user.courses or []

    return flask.redirect("/me")

@app.post("/logout")
def logout():
    flask.session.clear()
    return {"status": "logged out"}

@app.get("/me")
def me():
    if "user" not in flask.session:
        return {"user": None}

    return {
        "user": flask.session.get("user"),
        "role": flask.session.get("role"),
        "student_id": flask.session.get("student_id"),
        "courses": flask.session.get("courses"),
    }

@app.get("/students/<student_id>/profile")
def get_profile(student_id):
    profile = STUDENT_PROFILES.get(int(student_id))
    if profile is None:
        return {"error": "student not found"}, 404
    return flask.jsonify(profile)

# -----------------------------------------------------------------------------
# Grade authorization (V1: F04 + F05)
# -----------------------------------------------------------------------------

def current_user():
    """Return the authenticated User, re-loaded from USERS, or None.

    Role, student_id and courses are taken from the server-side USERS record,
    not from the copies stored in the session cookie.
    """
    username = flask.session.get("user")
    if username is None:
        return None
    return USERS.get(username)


def can_read_grade(user, row):
    if user.role == "admin":
        return True
    if user.role == "student":
        return user.student_id is not None and row["student_id"] == user.student_id
    if user.role == "professor":
        return row["course_id"] in (user.courses or [])
    return False


def can_write_grade(user, course_id):
    if user.role == "admin":
        return True
    if user.role == "professor":
        return course_id in (user.courses or [])
    return False  # students and unknown roles never write grades


def _unauthenticated():
    return {"error": "authentication required"}, 401


def _forbidden():
    return {"error": "forbidden"}, 403


@app.get("/grades/<student_id>")
def get_grades(student_id):
    user = current_user()
    if user is None:
        return _unauthenticated()

    sid = int(student_id)

    if user.role == "student" and user.student_id != sid:
        return _forbidden()
    if user.role not in ("student", "professor", "admin"):
        return _forbidden()

    rows = [
        row for row in GRADES
        if row["student_id"] == sid and can_read_grade(user, row)
    ]
    # R4: a professor with no permitted record for this student is denied
    # rather than given an empty list or other courses' grades.
    if user.role == "professor" and not rows:
        return _forbidden()
    return flask.jsonify(rows)

@app.post("/grades/update")
def update_grade():
    user = current_user()
    if user is None:
        return _unauthenticated()

    data = flask.request.get_json()

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]

    # Checked before find_grade(), so both the update and the append
    # branch are covered and a denied request changes nothing.
    if not can_write_grade(user, course_id):
        return _forbidden()

    row = find_grade(student_id, course_id)
    if row is None:
        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
    else:
        row["grade"] = grade

    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}

def resolve_material_path(raw_path: str) -> typing.Optional[pathlib.Path]:
    """Map an untrusted relative name to a regular file inside MATERIALS_DIR.

    Returns None for anything that is not such a file. MATERIALS_DIR is read on
    every call so that runtime reconfiguration (and monkeypatch) is honoured.
    """
    # 1. Lexical checks before touching the filesystem. Parse with Windows
    #    rules on every OS so "/" and "\" are both separators and drive
    #    letters ("C:x") and UNC prefixes ("//host/share") count as anchors.
    #    Rejecting anchors before resolve() also avoids touching UNC paths
    #    (network access) on Windows.
    if not raw_path or "\x00" in raw_path:
        return None
    relative = pathlib.PureWindowsPath(raw_path)
    if relative.anchor or ".." in relative.parts:
        return None

    # 2. Canonical containment check (also catches symlinks pointing outside).
    base = pathlib.Path(MATERIALS_DIR).resolve()
    try:
        target = base.joinpath(*relative.parts).resolve()
    except (OSError, ValueError):
        return None
    if not target.is_relative_to(base) or not target.is_file():
        return None
    return target


@app.get("/files")
def download_file():
    # Manual correction: use the same authentication rule as the grade
    # endpoints (V1) instead of only checking that the session has a "user" key.
    if current_user() is None:
        return _unauthenticated()

    target = resolve_material_path(flask.request.args.get("path", ""))
    if target is None:
        return {"error": "file not found"}, 404
    try:
        return flask.send_file(target)
    except FileNotFoundError:  # removed between the check and the open
        return {"error": "file not found"}, 404

@app.errorhandler(Exception)
def handle_error(exc):
    return {
        "error": str(exc),
        "type": exc.__class__.__name__,
    }, 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)