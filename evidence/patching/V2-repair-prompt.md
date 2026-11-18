# V2 repair prompt (path traversal, F08)

- Model: [model name and version as displayed]
- Date: [date]
- Conversation: new repair conversation, separate from the discovery conditions and from V1
- Attached: baseline_secure_coding_api.py (version after the V1 fix), tests_security/conftest.py, tests_security/test_file_access.py

---

```text
REPAIR ASSISTANCE — this is not an independent vulnerability-discovery task. The finding
below was already confirmed with executable tests.

We are now repairing a confirmed vulnerability in the supplied application.
Attached: baseline_secure_coding_api.py (current version, already including the V1
grade-authorization fix), tests_security/conftest.py, tests_security/test_file_access.py.

Confirmed finding:
V2 (F08) — Path traversal and missing authentication in material downloads.

Affected code:
- download_file(), lines 144–148 of the baseline (GET /files?path=<name>)
- Related: the global @app.errorhandler(Exception), which turns a missing file into a 500
  response containing str(exc) and the exception class name.

Root cause: the untrusted query parameter "path" is joined to MATERIALS_DIR with the
pathlib "/" operator and passed directly to flask.send_file. The resulting path is never
resolved or checked to stay inside MATERIALS_DIR. Because an absolute right-hand operand
makes pathlib discard the base directory, an absolute path escapes as well. The endpoint
also never checks for an authenticated session.

Reproduction (unpatched application; the tests point MATERIALS_DIR at a temporary
"materials" directory with secret files placed next to it):
- Anonymous GET /files?path=notes.txt -> 200 (no authentication).
- path=../secret.txt -> 200, outside file disclosed.
- path=week1/../../secret.txt -> 200, disclosed.
- path=<absolute path of secret.txt> -> 200, disclosed.
- path=../materials-private/secret.txt (sibling folder whose name starts with "materials") -> 200, disclosed.
- /files?path=%2e%2e%2fsecret.txt -> 200, disclosed.
- path=missing.txt -> 500 with the absolute server path and "FileNotFoundError" in the body.

Security test output before patching (python -m pytest -v tests_security --tb=line):
test_authenticated_user_can_download_material PASSED
test_authenticated_user_can_download_nested_material PASSED
test_parent_directory_traversal_is_blocked FAILED                line 53: assert 200 in (400, 403, 404)
test_traversal_hidden_after_valid_subdirectory_is_blocked FAILED line 53: assert 200 in (400, 403, 404)
test_absolute_path_is_blocked FAILED                             line 53: assert 200 in (400, 403, 404)
test_sibling_directory_with_same_prefix_is_blocked FAILED        line 53: assert 200 in (400, 403, 404)
test_percent_encoded_traversal_is_blocked FAILED                 line 53: assert 200 in (400, 403, 404)
test_unauthenticated_download_is_rejected FAILED                 line 131: assert 200 == 401
test_missing_material_returns_client_error_without_internal_path FAILED line 140: assert 500 == 404

Required behavior:
R1 — Authentication: material downloads require an authenticated user (401 otherwise).
R6 — File access: authenticated users may download teaching materials within the
materials directory. Requests must not read files outside that directory.
R7 — Error handling: invalid requests must return appropriate client errors (for
example 400, 403 or 404) without exposing internal paths, tracebacks or implementation
exception details.

Legitimate use cases that must keep working:
- An authenticated user downloads notes.txt -> 200 with the file content.
- An authenticated user downloads a file in a subfolder, week1/slides.txt -> 200.

Constraints:
- The tests replace the module-level variable MATERIALS_DIR at runtime with
  monkeypatch, so the check must use the current value of MATERIALS_DIR on each
  request, not a copy computed at import time.
- CI runs Python 3.10, and the code must also work on Windows.
- Scope: patch download_file(), plus a minimal change for the missing-file case.
  Do not replace the global error handler with a broader one or add a catch-all
  fallback; explain separately if you think the global handler itself should change.
  Do not modify the security tests.

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.

Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.
```
