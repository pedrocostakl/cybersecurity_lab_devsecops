I'll set up the project, write the patch, and run the security tests on it before and after the change.

Baseline reproduces (7 failed, 2 passed). Now the patch.

With the patch applied, all 9 security tests pass (they were 7 failed, 2 passed before). All 31 tests also pass on both Python 3.13 and Python 3.10, counting the 22 extra regression tests I added. I couldn't run anything on Windows, so the Windows behaviour is reasoned from how the code works, not tested.

## The diff

```diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -141,11 +141,46 @@
 
     return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}
 
+def resolve_material_path(raw_path: str) -> typing.Optional[pathlib.Path]:
+    """Map an untrusted relative name to a regular file inside MATERIALS_DIR.
+
+    Returns None for anything that is not such a file. MATERIALS_DIR is read on
+    every call so that runtime reconfiguration (and monkeypatch) is honoured.
+    """
+    # 1. Lexical checks before touching the filesystem. Parse with Windows
+    #    rules on every OS so "/" and "\" are both separators and drive
+    #    letters ("C:x") and UNC prefixes ("//host/share") count as anchors.
+    #    Rejecting anchors before resolve() also avoids touching UNC paths
+    #    (network access) on Windows.
+    if not raw_path or "\x00" in raw_path:
+        return None
+    relative = pathlib.PureWindowsPath(raw_path)
+    if relative.anchor or ".." in relative.parts:
+        return None
+
+    # 2. Canonical containment check (also catches symlinks pointing outside).
+    base = pathlib.Path(MATERIALS_DIR).resolve()
+    try:
+        target = base.joinpath(*relative.parts).resolve()
+    except (OSError, ValueError):
+        return None
+    if not target.is_relative_to(base) or not target.is_file():
+        return None
+    return target
+
+
 @app.get("/files")
 def download_file():
-    raw_path = flask.request.args.get("path", "")
-    target = MATERIALS_DIR / raw_path
-    return flask.send_file(target)
+    if "user" not in flask.session:
+        return {"error": "authentication required"}, 401
+
+    target = resolve_material_path(flask.request.args.get("path", ""))
+    if target is None:
+        return {"error": "file not found"}, 404
+    try:
+        return flask.send_file(target)
+    except FileNotFoundError:  # removed between the check and the open
+        return {"error": "file not found"}, 404
```

## The control

1. **Login check first (R1).** The endpoint returns 401 when there's no session user, before it reads the path or touches the filesystem. This is the same session check `/me` uses.
2. **Text checks on the path (R6).** These run before anything is read from disk:
   - Empty values and NUL bytes are rejected.
   - The value is parsed with Windows path rules on every OS, so `/` and `\` both count as separators.
   - Anything that starts at a root is rejected. That covers `/abs`, `C:\x`, the drive-relative `C:x`, and UNC paths like `//host/share` or `\\host\share`.
   - Any `..` part is rejected.
   
   This blocks the absolute-path escape, where pathlib's `/` operator throws away `MATERIALS_DIR`. Because these checks happen before `resolve()`, Windows never tries to open an attacker's UNC path, which could otherwise leak NTLM credentials.
3. **Final containment check (R6).** The code resolves both the materials folder and the target to real paths, then checks `Path.is_relative_to` (available from Python 3.9). That compares whole path parts, so `materials-private` doesn't count as inside `materials`, which a string-prefix check would get wrong. It also catches symlinks that point outside the folder. It then checks `is_file()`, which rejects directories and Windows device names like `NUL`.
4. **Errors (R7).** Every rejection gives the same generic 404 with no path and no exception name. A missing file and a blocked path look identical, so a 404 doesn't reveal whether something exists. The only exception caught is the narrow `FileNotFoundError` from `send_file`, for a file deleted between the check and the read. There's no catch-all.

`MATERIALS_DIR` is read on every request and wrapped in `Path()`, so the monkeypatched value works, and so does a plain string. The percent-encoded case needs no special handling: Flask decodes the query string once, and the result is then caught as `..`.

**Why not use `flask.send_from_directory`?** It relies on Werkzeug's `safe_join`. On Windows with Python 3.10, which is your CI setup, `safe_join` didn't catch UNC paths before Werkzeug 3.0.6 (CVE-2024-49766). It also doesn't check symlinks. The code above doesn't depend on the Werkzeug version. If you prefer `send_from_directory`, require Werkzeug ≥ 3.0.6 and still catch `NotFound` in the function itself, because the global error handler would otherwise turn it into a 500.

## Assumptions and limitations

- **Unpinned layers.** Containment is only enforced in the app. Deny-by-default file permissions for the process and a non-symlinked materials folder are still assumed.
- **Race window.** A symlink swapped in between the check and `send_file` could still escape. Closing that fully needs `O_NOFOLLOW`/`openat`-style opening, which isn't portable to Windows.
- **Stricter than before.** Any `..` is refused, even if it would stay inside the folder (e.g. `week1/../notes.txt`). On Linux, file names that contain a literal `\` can't be downloaded.
- **Same file for every user.** Any logged-in user can download any material. Nothing in R6 asks for per-course access control.
- **Windows-specific paths.** Behaviour with alternate data stream names (`notes.txt:stream`) and names with trailing dots isn't tested; containment still applies to them.

## Other affected paths

- **File reads:** `/files` is the only endpoint that reads files. Flask's built-in `/static` route already uses a safe join, and there's no `static/` folder.
- **The attached file doesn't appear to include the V1 fix.** `POST /grades/update` has no login or role check. `GET /grades/<id>` and `GET /students/<id>/profile` also have no login check, so they need the same R1 control.
- **`int(student_id)` on bad input:** `/students/abc/profile` returns 500 with the `ValueError` text in the body. I confirmed this, and it breaks R7.

## The global error handler (separate recommendation, not in the patch)

`@app.errorhandler(Exception)` also catches Werkzeug's HTTP exceptions. For example, `POST /files` returns **500** with `"type": "MethodNotAllowed"`. I'd split it into two:
- An `HTTPException` handler that keeps the original status code and returns a generic message.
- An `Exception` handler that logs the details on the server and returns `{"error": "internal error"}`, 500, with no `str(exc)` and no class name.

Separately, `debug=True` on `0.0.0.0` and the hard-coded `SECRET_KEY` are serious problems if this is ever deployed.

## Additional regression tests

These are in `test_file_access_extra.py`:
- **Escape attempts are denied:** paths with `\` separators, double encoding, `....//`, `C:x`, `C:\…`, UNC paths in both slash styles, `/etc/passwd`, a NUL byte, an empty value, `.`, a directory name and `week1/`. Each must also not leak the internal path.
- **Missing `path` parameter:** returns 404.
- **Symlink:** a symlink inside the folder that points outside is blocked. This test is skipped on Windows.
- **Logged out:** without a session, traversal paths and absolute paths both get 401. A session after logout also gets 401.
- **`MATERIALS_DIR`:** a change is picked up on the next request, and a `str` value still works.

I'd also add a Windows job to CI, so the Windows-only cases are actually exercised there.