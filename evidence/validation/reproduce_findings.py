"""Reproduce the consolidated findings (F01-F17) against the UNMODIFIED baseline.

Run from the repository root:

    python evidence/validation/reproduce_findings.py > evidence/validation/reproduction-baseline.txt

Each check prints the request, the observed behaviour, and whether the
behaviour violates the exercise requirements (R1-R7). It uses Flask's test
client only; no network service, OS file, or real data is touched. Files used
for the traversal checks are created in a temporary directory.
"""

import copy
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import baseline_secure_coding_api as api  # noqa: E402

ORIGINAL_GRADES = copy.deepcopy(api.GRADES)
results = []


def reset():
    api.GRADES[:] = copy.deepcopy(ORIGINAL_GRADES)


def client(user=None, password=None):
    c = api.app.test_client()
    if user:
        r = c.post("/login", data={"username": user, "password": password})
        assert r.status_code == 302, r.status_code
    return c


def record(fid, title, request, response, violated, note=""):
    body = response.get_data(as_text=True).strip().replace("\n", " ")
    if len(body) > 160:
        body = body[:157] + "..."
    verdict = "VIOLATION" if violated else "ok"
    results.append((fid, verdict))
    print(f"[{fid}] {verdict:9} {title}")
    print(f"       request : {request}")
    print(f"       response: {response.status_code} {body}")
    if note:
        print(f"       note    : {note}")


ALICE = ("alice", "alicepw")
PROF = ("prof_srs", "profpw")
ADMIN = ("admin1", "adminpw")

print("Baseline reproduction of consolidated findings")
print("=" * 72)

# F01 - Missing authentication (R1)
anon = client()
for path in ["/students/1001/profile", "/grades/1001", "/files?path=srs-summary.txt"]:
    r = anon.get(path)
    record("F01", "unauthenticated read", f"GET {path} (no session)", r, r.status_code != 401)
reset()
r = anon.post("/grades/update", json={"student_id": 1001, "course_id": "SRS", "grade": 0})
record("F01", "unauthenticated grade update", "POST /grades/update grade=0 (no session)", r,
       r.status_code != 401, f"stored grade now {api.find_grade(1001, 'SRS')['grade']} (was 14)")
reset()

# F02 - Student IDOR on profile and grades (R2)
c = client(*ALICE)
r = c.get("/students/1002/profile")
record("F02", "student reads another student's profile", "alice: GET /students/1002/profile", r, r.status_code != 403)
r = c.get("/grades/1002")
record("F02", "student reads another student's grades", "alice: GET /grades/1002", r, r.status_code != 403)

# F03 - Professor reads student profile (R3)
c = client(*PROF)
r = c.get("/students/1001/profile")
record("F03", "professor reads a student profile", "prof_srs: GET /students/1001/profile", r, r.status_code != 403)

# F04 - Professor reads grades outside assigned course / no filtering (R3, R4)
r = c.get("/grades/1001")
leaked = [row for row in (r.get_json() or []) if row["course_id"] not in ("SRS",)]
record("F04", "professor grade list not filtered by course", "prof_srs: GET /grades/1001", r, bool(leaked),
       f"out-of-scope rows returned: {leaked}")

# F05 - Grade update authorization (R3, R4)
reset()
r = c.post("/grades/update", json={"student_id": 1001, "course_id": "SSD", "grade": 0})
record("F05", "professor updates grade of unassigned course", "prof_srs: POST SSD grade=0", r, r.status_code != 403,
       f"stored SSD grade now {api.find_grade(1001, 'SSD')['grade']} (was 16)")
reset()
s = client(*ALICE)
r = s.post("/grades/update", json={"student_id": 1001, "course_id": "SRS", "grade": 20})
record("F05", "student updates own grade", "alice: POST SRS grade=20", r, r.status_code != 403,
       f"stored grade now {api.find_grade(1001, 'SRS')['grade']} (was 14)")
reset()

# F06 - Grade-update input validation (R5, R7)
a = client(*ADMIN)
cases = [
    ("grade above range", {"student_id": 1001, "course_id": "SRS", "grade": 25}),
    ("negative grade", {"student_id": 1001, "course_id": "SRS", "grade": -1}),
    ("boolean grade", {"student_id": 1001, "course_id": "SRS", "grade": True}),
    ("string grade", {"student_id": 1001, "course_id": "SRS", "grade": "A+"}),
    ("unknown course", {"student_id": 1001, "course_id": "XYZ", "grade": 10}),
    ("nonexistent student", {"student_id": 9999, "course_id": "SRS", "grade": 10}),
    ("student id as string", {"student_id": "1001", "course_id": "SRS", "grade": 10}),
    ("missing grade field", {"student_id": 1001, "course_id": "SRS"}),
    ("JSON array body", [1, 2, 3]),
]
for name, payload in cases:
    reset()
    r = a.post("/grades/update", json=payload)
    changed = api.GRADES != ORIGINAL_GRADES
    record("F06", f"invalid update: {name}", f"admin1: POST {payload}", r,
           r.status_code != 400 or changed, f"GRADES changed: {changed}")
reset()

# F07 - Student identifier validation (R5, R7)
for sid in ["abc", "0", "-1"]:
    r = a.get(f"/grades/{sid}")
    record("F07", f"student id '{sid}'", f"admin1: GET /grades/{sid}", r, r.status_code != 400)

# F08 - Path traversal (R6)
with tempfile.TemporaryDirectory() as tmp:
    tmp = pathlib.Path(tmp)
    materials = tmp / "materials"
    materials.mkdir()
    (materials / "notes.txt").write_text("allowed teaching material", encoding="utf-8")
    secret = tmp / "secret.txt"
    secret.write_text("TOP-SECRET-OUTSIDE-MATERIALS", encoding="utf-8")
    original_dir = api.MATERIALS_DIR
    api.MATERIALS_DIR = materials
    try:
        u = client(*ALICE)
        r = u.get("/files?path=notes.txt")
        record("F08", "legitimate material download", "alice: GET /files?path=notes.txt", r, r.status_code != 200)
        for p in ["../secret.txt", "sub/../../secret.txt", str(secret)]:
            r = u.get("/files", query_string={"path": p})
            leaked = b"TOP-SECRET" in r.data
            record("F08", "read outside materials dir", f"alice: GET /files?path={p}", r, leaked,
                   f"outside content disclosed: {leaked}")
            r.close()
    finally:
        api.MATERIALS_DIR = original_dir

# F09 - Error handler discloses internals and maps every error to 500 (R7)
r = a.get("/files?path=does-not-exist.txt")
record("F09", "missing file leaks absolute server path", "admin1: GET /files?path=does-not-exist.txt", r,
       str(api.BASE_DIR) in r.get_data(as_text=True) or r.status_code == 500)
r = anon.get("/no-such-route")
record("F09", "unknown route returns 500 instead of 404", "GET /no-such-route", r, r.status_code == 500)
r = anon.get("/login")
record("F09", "wrong method returns 500 instead of 405", "GET /login", r, r.status_code == 500)

# F10 - Hard-coded SECRET_KEY allows session forgery (R4 trust in session claims)
serializer = api.app.session_interface.get_signing_serializer(api.app)
forged = serializer.dumps({"user": "admin1", "role": "admin", "student_id": None, "courses": []})
f = api.app.test_client()
f.set_cookie("session", forged)
r = f.get("/me")
record("F10", "forged cookie signed with 'dev-secret-key'", "GET /me with forged admin cookie", r,
       (r.get_json() or {}).get("role") == "admin")

# F11 - Plaintext hard-coded credentials
print(f"[F11] code fact  plaintext passwords in USERS: {[u.password for u in api.USERS.values()]}")

# F12 - debug=True / host 0.0.0.0
src = (ROOT / "baseline_secure_coding_api.py").read_text(encoding="utf-8")
dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
print(f"[F12] code fact  'debug=True' in source: {'debug=True' in src}; "
      f"Dockerfile runs the __main__ block: {'baseline_secure_coding_api.py' in dockerfile.splitlines()[-1]}")

# F13 - Session cookie attributes
r = client().post("/login", data={"username": "alice", "password": "alicepw"})
print(f"[F13] observed   Set-Cookie: {r.headers.get('Set-Cookie')}")
print("       note    : HttpOnly is set by Flask's default; Secure and SameSite are absent.")

# F16 - Session fixation claim (Flask uses signed client-side cookies)
c = api.app.test_client()
c.set_cookie("session", serializer.dumps({"attacker": "fixed"}))
r = c.post("/login", data={"username": "alice", "password": "alicepw"})
print(f"[F16] observed   pre-login cookie value replaced at login: "
      f"{'session=' in (r.headers.get('Set-Cookie') or '')}; no server-side session id exists to fix.")

# F17 - Session cookie remains valid after logout (stateless cookie, no revocation)
c = client(*ALICE)
stolen = c.get_cookie("session").value
c.post("/logout")
replay = api.app.test_client()
replay.set_cookie("session", stolen)
r = replay.get("/me")
record("F17", "cookie captured before logout still accepted", "GET /me with pre-logout cookie", r,
       (r.get_json() or {}).get("user") == "alice")

print("=" * 72)
violations = sorted({fid for fid, v in results if v == "VIOLATION"})
print("Findings with at least one reproduced violation:", ", ".join(violations))
