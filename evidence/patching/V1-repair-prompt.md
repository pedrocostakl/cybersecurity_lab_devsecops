# V1 repair prompt (grade authorization, F04 + F05)

- Model: Opus 5.5
- Conversation: new repair conversation, separate from the discovery conditions A, B and C
- Attached: baseline_secure_coding_api.py, tests_security/conftest.py, tests_security/test_grade_authorization.py

---

```text
REPAIR ASSISTANCE — this is not an independent vulnerability-discovery task. The finding
below was already confirmed with executable tests.

We are now repairing a confirmed vulnerability in the supplied application.
Attached: baseline_secure_coding_api.py, tests_security/conftest.py,
tests_security/test_grade_authorization.py.

Confirmed finding:
V1 (F04 + F05) — Missing user-, record- and course-level authorization on the grade endpoints.

Affected code:
- get_grades(), lines 122–126 (GET /grades/<student_id>)
- update_grade(), lines 128–142 (POST /grades/update), including the branch that appends
  a new record when none exists.

Root cause: login() stores user, role, student_id and courses in flask.session, but neither
grade endpoint reads the session. get_grades() returns every record for the requested
student_id, and update_grade() writes or appends any student/course/grade it receives.
Authorization is never derived from the session or compared with the record being read
or written.

Reproduction (unpatched application, Flask test client):
- Anonymous POST /grades/update {"student_id":1001,"course_id":"SRS","grade":0} -> 200, data changed.
- prof_srs (courses ["SRS"]) POST {"student_id":1001,"course_id":"SSD","grade":0} -> 200, Alice's SSD grade 16 -> 0.
- prof_srs POST {"student_id":1002,"course_id":"SSD","grade":20} -> 200, a new SSD record is appended.
- alice (student 1001) POST {"student_id":1001,"course_id":"SRS","grade":20} -> 200, her own grade 14 -> 20.
- Anonymous GET /grades/1001 -> 200 with grades.
- alice GET /grades/1002 -> 200 with Bob's grades.
- prof_srs GET /grades/1001 -> 200 including the SSD record.

Security test output before patching (python -m pytest -v tests_security --tb=line):
test_assigned_professor_can_update_grade PASSED
test_admin_can_update_any_course_grade PASSED
test_student_can_read_own_grades PASSED
test_admin_can_read_all_grades_of_a_student PASSED
test_professor_cannot_update_grade_in_unassigned_course FAILED   line 83: assert 200 == 403
test_student_cannot_update_own_grade FAILED                      line 97: assert 200 == 403
test_unauthenticated_update_is_rejected_without_change FAILED    line 109: assert 200 == 401
test_professor_cannot_create_record_in_unassigned_course FAILED  line 124: assert 200 == 403
test_student_cannot_read_another_students_grades FAILED          line 136: assert 200 == 403
test_professor_grade_list_is_filtered_to_assigned_courses FAILED line 149: list contains one more item: {'course_id': 'SSD', 'grade': 16, 'student_id': 1001}
test_professor_denied_when_no_permitted_records FAILED           line 162: assert 200 == 403
test_unauthenticated_grade_read_is_rejected FAILED               assert 200 == 401

Required behavior:
R1 — Authentication: grade access and grade updates require an authenticated user.
R2 — Student privacy: students may read only their own grades.
R3 — Academic staff scope: professors may read and update grades only for their assigned
courses. Administrators may read grades and update grades.
R4 — Complete authorization: check authorization on every relevant request. Login alone,
a valid identifier, or a role name alone does not establish permission for a particular
record. For a grade-list response, return only records the requester is authorized to
read. Deny a request that has no permitted records; do not disclose other grades.
R7 — Error handling: unauthenticated protected requests return 401; authenticated but
unauthorized requests return 403, without exposing internal paths, tracebacks or exception
details. A denied update must leave stored data unchanged (no modification and no new record).

Legitimate use cases that must keep working:
- prof_srs updates a grade in SRS -> 200 and the new grade is stored.
- admin1 updates a grade in any course -> 200.
- alice reads /grades/1001 -> 200 with exactly her own records.
- admin1 reads any student's grades -> 200 with all of that student's records.
- prof_srs reads /grades/1001 -> 200 with only the SRS record.
Keep the existing success response formats unchanged (the update returns
{"status":"ok", ...}; the grade read returns a JSON list of records).

Scope: patch only the grade endpoints (a small shared helper is acceptable). Grade-update
input validation (R5), the student-profile endpoint, the global error handler and the
configuration (secret key, debug mode, host binding) are separate findings: do not change
them here, but list them if they need the same control. Do not modify the security tests.
The existing functional test tests/test_api.py::test_get_student_grades reads /grades/1001
without logging in and expects 200, which contradicts R1; tell me how that expectation
should be updated without deleting coverage.

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.

Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.
```
