# V1 follow-ups: grade authorization (F04 + F05)

Original suggestion: [V1-initial-response.md](V1-initial-response.md) (kept unedited).
No further requests were sent to the model for V1.

## Review before applying

The patch was applied to a scratch copy of the repository first and checked with the
security tests, the functional tests and extra manual requests.

| Check | Result |
| --- | --- |
| `tests_security/test_grade_authorization.py` | 12 passed (8 failed before the patch) |
| Session cookie for `prof_srs` with `role="admin"` and courses `["SRS","SSD"]`, POST SSD | 403: role and courses are reloaded from `USERS`, not trusted from the cookie |
| Session naming a nonexistent user, GET `/grades/1001` | 401 |
| `tests/test_api.py::test_get_student_grades` | Failed with `401 == 200`, expected because anonymous reads now violate R1 |
| The model's proposed replacement for that functional test | Error `fixture 'client' not found`: the `client` fixture exists only in `tests_security/conftest.py` |

## Changes compared with the model's suggestion

1. **Application code:** applied as suggested, with no change to the logic. The diff hunk
   header in the response did not match its content exactly, so the change was applied by
   hand instead of with `git apply`.
2. **Functional test (manual correction):** the model's version of
   `test_get_student_grades` used a nonexistent `client` fixture. It was rewritten in the
   existing style of `tests/test_api.py` (`app.test_client()`):
   - `test_get_student_grades` now logs in as `alice` (the owning student) and keeps all
     original assertions unchanged;
   - a new `test_get_student_grades_requires_login` checks that anonymous access returns 401.

   No assertion was weakened, and the original version is kept in the Git history.

## Accepted limitations (outside the scope of V1)

- R5 input validation is unchanged: `/grades/abc` returns 500 with the `ValueError` text,
  missing fields return 500 with `KeyError`, and a professor can create a grade for a
  nonexistent student in their own course.
- An admin reading a student with no grades gets `200 []`. This was accepted under R4,
  because the admin is allowed to read every record of that student and there are none.
- The hard-coded `SECRET_KEY` (F10) still allows forged session cookies for any existing
  user.
