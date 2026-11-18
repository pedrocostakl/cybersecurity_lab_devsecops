# V2 follow-ups: path traversal (F08)

Original suggestion: [V2-initial-response.md](V2-initial-response.md) (kept unedited).
No further requests were sent to the model for V2.

## Deviation from the prompt

The prompt header says the V1-patched source was attached, but the baseline source was
attached instead. The model noticed this ("The attached file doesn't appear to include
the V1 fix"). The two patches change different functions (`get_grades` / `update_grade`
versus `download_file`), so they were combined without conflict. This deviation explains
the inconsistent authentication check corrected below.

## Review before applying

The patch was applied to a scratch copy together with V1 and checked with the security
tests, the functional tests and extra manual requests.

| Check | Result |
| --- | --- |
| `tests_security/test_file_access.py` | 9 passed (7 failed before the patch) |
| `week1/../srs-summary.txt` (stays inside the folder) | 404: stricter than required, accepted |
| Session naming a nonexistent user, GET `/files?path=srs-summary.txt` | **200** with the model's patch; 401 for `/grades` |
| Exception handling | Only `FileNotFoundError` is caught; the global handler is unchanged |

## Changes compared with the model's suggestion

1. **Authentication check (manual correction).** The model checked
   `"user" in flask.session`. V1 uses `current_user()`, which reloads the user from
   `USERS`. With the model's version, a session naming a nonexistent user was refused by
   `/grades` but could still download materials. Exploiting this needs a forged cookie,
   which is possible only because of the hard-coded key (F10), so it is low severity. The
   check was nevertheless replaced with `current_user()` / `_unauthenticated()`, so every
   protected endpoint shares one authentication rule. After the change, the same request
   returns 401.
2. **Everything else** (`resolve_material_path()`, the 404 responses and the narrow
   `FileNotFoundError` catch) was applied as suggested, by hand instead of with
   `git apply`.

## Accepted limitations

- Any `..` is rejected, even when the path would stay inside the materials folder.
- Any logged-in user can download any material; R6 does not ask for per-course access.
- A symlink swapped in between the check and `send_file` (a race condition) is not
  prevented.
- The global error handler still returns `str(exc)` and the exception name for other
  endpoints. The model recommended fixing it separately; that is out of scope here.
- The model's extra tests (`test_file_access_extra.py`) were not delivered and were not
  added to the repository.
