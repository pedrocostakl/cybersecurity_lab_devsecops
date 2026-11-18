# Selected findings for validation and repair (Sections 8–10)

Two findings with different root causes were selected from the [consolidated table](findings-table.md).

| # | Category required | Finding | Root cause |
| --- | --- | --- | --- |
| V1 | Authorization (user, resource or course permission) | **F04 + F05: grade authorization** for `GET /grades/<id>` and `POST /grades/update` | Authorization is never derived from the session. The role, owning student and assigned courses are not compared with the record being read or written. |
| V2 | File access | **F08: path traversal** in `GET /files?path=` | The untrusted path is joined to `MATERIALS_DIR` and passed to `send_file` without resolving it and checking that it stays inside the directory. |

Neither repair can be satisfied by a login check alone. V1 needs per-course and per-student decisions; V2 needs path canonicalisation and containment. Moving secrets, disabling debug mode and changing the bind address (F10–F12) were excluded, as the assignment requires.

## V1: Grade authorization (F04, F05)

**Affected code:** `get_grades()` L122–126 and `update_grade()` L128–142.

**Requirements:** R1, R2, R3, R4, R7.

**Discovery coverage:** F05 was detected in every condition. F04 (professor scope on reads) was detected only in condition C, and was partially suggested as a test in Run 2 A and B.

**Tests:** [`tests_security/test_grade_authorization.py`](../../tests_security/test_grade_authorization.py)

| Test | Kind | What it checks | Pre-patch |
| --- | --- | --- | --- |
| `test_assigned_professor_can_update_grade` | supplied example (not assessed) | prof_srs updates SRS | PASS |
| `test_admin_can_update_any_course_grade` | legitimate | Admin may update any course (R3) | PASS |
| `test_student_can_read_own_grades` | legitimate | Alice gets exactly her own 2 rows (R2) | PASS |
| `test_admin_can_read_all_grades_of_a_student` | legitimate | Admin sees all courses (R3) | PASS |
| `test_professor_cannot_update_grade_in_unassigned_course` | malicious + state | prof_srs → SSD gets 403 and `GRADES` is unchanged | **FAIL** `200 == 403` |
| `test_student_cannot_update_own_grade` | variation | Owning the record does not grant write access | **FAIL** `200 == 403` |
| `test_unauthenticated_update_is_rejected_without_change` | malicious + state | Anonymous write gets 401 and data is unchanged (R1, R7) | **FAIL** `200 == 401` |
| `test_professor_cannot_create_record_in_unassigned_course` | variation | The *append* branch (no existing row) is also guarded | **FAIL** `200 == 403` |
| `test_student_cannot_read_another_students_grades` | malicious | Alice → `/grades/1002` gets 403 (R2) | **FAIL** `200 == 403` |
| `test_professor_grade_list_is_filtered_to_assigned_courses` | variation | prof_srs gets only the SRS row and no SSD row (R4 filtering) | **FAIL** SSD row returned |
| `test_professor_denied_when_no_permitted_records` | variation | No permitted rows gets 403, not other courses' grades (R4) | **FAIL** `200 == 403` |
| `test_unauthenticated_grade_read_is_rejected` | malicious | Anonymous read gets 401 (R1) | **FAIL** `200 == 401` |

**Observed pre-patch behaviour:**

- `prof_srs` overwrote Alice's SSD grade (16 → 0).
- Alice raised her own SRS grade (14 → 20).
- `prof_srs` received Alice's SSD grade in `GET /grades/1001`.

See [`reproduction-baseline.txt`](reproduction-baseline.txt), entries F04 and F05.

## V2: Path traversal in material downloads (F08)

**Affected code:** `download_file()` L144–148.

**Requirements:** R6, R1, R7.

**Discovery coverage:** Detected in every LLM condition. Missed by Bandit and by Semgrep `p/python`.

**Tests:** [`tests_security/test_file_access.py`](../../tests_security/test_file_access.py)

These tests use `tmp_path` and `monkeypatch` to point `api.MATERIALS_DIR` at a temporary `materials/` directory. That directory has a sentinel file next to it and another inside a sibling directory, `materials-private/`.

| Test | Kind | What it checks | Pre-patch |
| --- | --- | --- | --- |
| `test_authenticated_user_can_download_material` | legitimate | A file inside the materials directory downloads | PASS |
| `test_authenticated_user_can_download_nested_material` | legitimate | A file in a subfolder still works | PASS |
| `test_parent_directory_traversal_is_blocked` | malicious | `../secret.txt` | **FAIL** 200, sentinel disclosed |
| `test_traversal_hidden_after_valid_subdirectory_is_blocked` | variation | `week1/../../secret.txt` defeats a "no leading `..`" filter | **FAIL** 200, sentinel disclosed |
| `test_absolute_path_is_blocked` | variation | An absolute path makes pathlib discard the base, so `..` filtering does not help | **FAIL** 200, sentinel disclosed |
| `test_sibling_directory_with_same_prefix_is_blocked` | variation | `../materials-private/secret.txt` defeats a `str.startswith` containment check | **FAIL** 200, sentinel disclosed |
| `test_percent_encoded_traversal_is_blocked` | variation | `%2e%2e%2fsecret.txt` | **FAIL** 200, sentinel disclosed |
| `test_unauthenticated_download_is_rejected` | malicious | Anonymous download gets 401 (R1) | **FAIL** `200 == 401` |
| `test_missing_material_returns_client_error_without_internal_path` | malicious | A missing file gets 404 with no absolute path or exception class (R7) | **FAIL** `500 == 404` |

There is no stored state to check for V2, because downloads do not modify data.

## Pre-patch results

- **Local:** [`pre-patch-security-tests-local.txt`](pre-patch-security-tests-local.txt) shows **15 failed, 6 passed**. All 6 passing tests are legitimate operations. Every failure is a security assertion (wrong status or disclosed data). None is an import error, broken fixture or missing dependency.
- **CI (before patching):** https://github.com/pedrocostakl/cybersecurity_lab_devsecops/actions/runs/44351630347. `Selected security regression tests` failed and `Build and test Docker image` was skipped.

## Check that the tests reject incomplete patches

The tests were also run against a throwaway, out-of-repo copy of the application. That copy held a correct reference fix plus three deliberately incomplete variants. The repository application was **not** modified, because the patch must come from the LLM repair step in Part IV.

| Application variant | Result |
| --- | --- |
| Correct fix (session-based role, course and owner checks; `resolve()` + `is_relative_to()`) | 21 passed |
| Containment via `str(target).startswith(str(MATERIALS_DIR))` | 1 failed: `test_sibling_directory_with_same_prefix_is_blocked` |
| Professor reads allowed by role only (no course filter) | 2 failed: filtering and deny-when-empty tests |
| Updates blocked for students only (no course check for professors) | 2 failed: both unassigned-course update tests |

This shows that every malicious test can be satisfied by a correct fix, and that the variation tests catch the typical partial fixes.

## Note for Part V (functional tests)

`tests/test_api.py::test_get_student_grades` calls `/grades/1001` **without logging in** and expects 200, so the V1 repair will make it fail. `test_get_student_profile` will fail too if profile authorization (F01–F03) is also repaired. As the assignment instructs, they will need to be updated after patching: log in as an authorised user for the positive case, and add a separate denial check. They must not be deleted.
