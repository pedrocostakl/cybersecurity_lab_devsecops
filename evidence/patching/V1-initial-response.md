I'll patch the two grade endpoints, run your security tests against the patched copy, and return the diff with the explanation.

All 12 pass. Next I'll write the suggested regression tests and run them against the patch.

I've patched both grade endpoints. All 12 of your security tests pass, and I didn't change any of them. 8 of the 9 regression tests I added fail on the unpatched code; the one that passes there is a check that legitimate use still works. Only `baseline_secure_coding_api.py` changes.

## Unified diff

```diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -119,20 +119,88 @@
         return {"error": "student not found"}, 404
     return flask.jsonify(profile)
 
+# -----------------------------------------------------------------------------
+# Grade authorization (V1: F04 + F05)
+# -----------------------------------------------------------------------------
+
+def current_user():
+    """Return the authenticated User, re-loaded from USERS, or None.
+
+    Role, student_id and courses are taken from the server-side USERS record,
+    not from the copies stored in the session cookie.
+    """
+    username = flask.session.get("user")
+    if username is None:
+        return None
+    return USERS.get(username)
+
+
+def can_read_grade(user, row):
+    if user.role == "admin":
+        return True
+    if user.role == "student":
+        return user.student_id is not None and row["student_id"] == user.student_id
+    if user.role == "professor":
+        return row["course_id"] in (user.courses or [])
+    return False
+
+
+def can_write_grade(user, course_id):
+    if user.role == "admin":
+        return True
+    if user.role == "professor":
+        return course_id in (user.courses or [])
+    return False  # students and unknown roles never write grades
+
+
+def _unauthenticated():
+    return {"error": "authentication required"}, 401
+
+
+def _forbidden():
+    return {"error": "forbidden"}, 403
+
+
 @app.get("/grades/<student_id>")
 def get_grades(student_id):
+    user = current_user()
+    if user is None:
+        return _unauthenticated()
+
     sid = int(student_id)
-    rows = [row for row in GRADES if row["student_id"] == sid]
+
+    if user.role == "student" and user.student_id != sid:
+        return _forbidden()
+    if user.role not in ("student", "professor", "admin"):
+        return _forbidden()
+
+    rows = [
+        row for row in GRADES
+        if row["student_id"] == sid and can_read_grade(user, row)
+    ]
+    # R4: a professor with no permitted record for this student is denied
+    # rather than given an empty list or other courses' grades.
+    if user.role == "professor" and not rows:
+        return _forbidden()
     return flask.jsonify(rows)
 
 @app.post("/grades/update")
 def update_grade():
+    user = current_user()
+    if user is None:
+        return _unauthenticated()
+
     data = flask.request.get_json()
 
     student_id = data["student_id"]
     course_id = data["course_id"]
     grade = data["grade"]
 
+    # Checked before find_grade(), so both the update and the append
+    # branch are covered and a denied request changes nothing.
+    if not can_write_grade(user, course_id):
+        return _forbidden()
+
     row = find_grade(student_id, course_id)
     if row is None:
         GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
```

## The control being implemented

Each grade request now has its permissions checked on the server, against the specific record it reads or writes:

- **Who is asking (R1):** `current_user()` takes only the username from the session and loads the rest from `USERS`. Without a valid user the request gets a 401 before the body is parsed or any data is touched. The role and courses copied into the cookie at login are never trusted, so a stale or tampered cookie can't widen access.
- **Read (R2, R3, R4):** a student asking for another student's ID gets a 403 before any rows are looked at. That 403 is the same whether or not the ID exists, so IDs can't be probed this way. For everyone else, each row is checked with `can_read_grade`, so a professor only gets rows from assigned courses. If a professor ends up with no permitted rows, the request is denied with 403 instead of returning an empty list.
- **Write (R3, R4, R7):** `can_write_grade` allows admins, and professors only for their assigned `course_id`. Students and unknown roles are never allowed. The check runs before `find_grade()`, so it covers both the "update existing row" branch and the "append new row" branch, and a denied request leaves `GRADES` unchanged.
- **Unknown roles are denied by default.** Successful responses keep their existing format, and denial bodies are fixed messages with no exception details.

## Remaining assumptions and limitations

- **Empty lists:** I applied the "deny when nothing is permitted" rule to professors only. A student reading their own grades, or an admin reading any student's, gets `200 []` when there are none, because they're allowed to see all of that student's records and there simply aren't any. If you read R4 as "always deny when the result is empty," move the empty check up so it applies to every role.
- **Matching is exact:** course IDs must match exactly (`"srs"` doesn't match `"SRS"`) and student IDs are compared as integers. A JSON `student_id` sent as `"1001"` (a string) still passes the course check and gets stored as a string. That's input validation (R5), which isn't fixed here.
- **R5 / R7 leftovers on these endpoints:** a non-numeric `/grades/abc`, or an update with missing keys or a non-JSON body, still goes to the global error handler. That handler returns the exception text with a 500. Every one of these paths now requires login first, but the leak remains until R5 and the error-handler finding are fixed.
- **Session trust depends on the secret key:** the hardcoded `SECRET_KEY` lets anyone forge a session cookie for any username, including `admin1`. Until the configuration finding is fixed, this control can be bypassed.
- **Not addressed here:** session revocation (deleting a user does block them, because `current_user()` returns None) and CSRF on `POST /grades/update`. CSRF risk is reduced because `get_json()` needs an `application/json` body, but there's no token and no explicit SameSite setting.

## Other paths that need the same control (not changed, as instructed)

- **`GET /students/<student_id>/profile`:** no authentication or ownership check, so anyone can read any student's name, email and program. It needs `current_user()` plus a student-owns-it / staff check.
- **`GET /files`:** no authentication (on top of its path-traversal finding).
- **Global error handler:** returns `str(exc)` and the exception class name.
- **Configuration:** the hardcoded secret key, `debug=True` and `host="0.0.0.0"`.

## Updating `tests/test_api.py::test_get_student_grades`

Don't delete the test; split it into two checks:

```python
def test_get_student_grades(client):
    client.post("/login", data={"username": "alice", "password": "alicepw"})
    response = client.get("/grades/1001")
    assert response.status_code == 200
    # keep the original body assertions here, unchanged

def test_get_student_grades_requires_login(client):
    response = client.get("/grades/1001")
    assert response.status_code == 401
```

The first test keeps the original functional coverage of the read and the JSON list format, now as an authenticated owner. The second records the new R1 contract. If the original assertions expect every course for student 1001, log in as alice or admin1, not prof_srs.

## Suggested regression tests (in `test_grade_authorization_extra.py`)

- **Bob can't read Alice's grades:** the student check works for both students, not just Alice.
- **Probing a non-existent ID:** a student requesting `/grades/9999` gets 403, not 404, so IDs can't be enumerated.
- **Logout:** after logging out, reads return 401.
- **Tampered session:** a session saying prof_srs has `role="admin"` and courses `["SRS","SSD"]` still can't update SSD. This proves the role comes from `USERS`, not the cookie.
- **Unknown user:** a session for a username that doesn't exist gets 401.
- **Exact course match:** `"srs"`, `"SRS "` and `["SRS"]` as the course are all rejected with no data change.
- **Student creating a record:** a student trying to add a new grade row gets 403.
- **Professor creating a record in their own course:** gets 200 with the response format unchanged.
- **Denial bodies:** 401 and 403 responses contain no traceback, file path, exception type or grade data.