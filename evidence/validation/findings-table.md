# Consolidated findings table (Section 7)

Target: `baseline_secure_coding_api.py` at commit `14afdb2` (unchanged during discovery).
Scanner reports: [`evidence/baseline-sast/bandit.json`](../baseline-sast/bandit.json) (Bandit 1.9.4) and
[`evidence/baseline-sast/semgrep.json`](../baseline-sast/semgrep.json) (Semgrep 1.183.0, `p/python`).
Dynamic evidence: [`reproduction-baseline.txt`](reproduction-baseline.txt), produced by
[`reproduce_findings.py`](reproduce_findings.py) against the unmodified baseline.

## How the LLM columns are read

Two independent discovery runs were made with the same prompts:

| Run | Files | 
| --- | --- |
| Run 1 | [`A-response.md`](../discovery/A-response.md), [`B-response.md`](../discovery/B-response.md), [`C-response.md`](../discovery/C-response.md) |
| Run 2 | [`Luis-A-response.md`](../discovery/Luis-A-response.md), [`Luis-B-response.md`](../discovery/Luis-B-response.md), [`Luis-C-response.md`](../discovery/Luis-C-response.md) |

Each A/B/C cell is written as **Run 1 / Run 2**.

- **✓**: detected. The response locates the affected operation and explains the missing or incorrect check.
- **◐**: partial. It is mentioned only as a side observation, a proposed test, or an error trigger, or the response leaves the policy open and does not claim a violation.
- **✗**: not reported.

Following the assignment, saying "implement RBAC" without locating the omission is not counted as ✓.

## Table

| ID | Root cause and affected operation | Bandit rule | Semgrep rule | A | B | C | Validation status | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| F01 | **Missing authentication** (R1): `get_profile` L115, `get_grades` L122, `update_grade` L128 and `download_file` L144 never check `flask.session`. | — | — | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | **Confirmed** | Anonymous `GET /students/1001/profile`, `/grades/1001` and `/files?path=…` all return 200. An anonymous `POST /grades/update` sets SRS grade 14→0. |
| F02 | **Student object-level authorization (IDOR)** (R2): profile and grade lookups use the URL `student_id` and are never compared with `session["student_id"]`. | — | — | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | **Confirmed** | Alice receives Bob's profile and grades (200). |
| F03 | **Professor can read student profiles** (R3): `get_profile` has no role check. | — | — | ✗ / ✗ | ✗ / ✗ | ✓ / ✓ | **Confirmed** (policy-dependent before C) | `prof_srs` receives Alice's profile (200). In Run 2 B, the model explicitly *assumed* professors may read profiles. |
| F04 | **Professor grade reads are not limited to assigned courses** (R3, R4): `get_grades` returns every row for the student. There is no `course_id ∈ session["courses"]` filter and no denial when nothing is permitted. | — | — | ✗ / ◐ | ✗ / ◐ | ✓ / ✓ | **Confirmed** | `prof_srs` (SRS only) receives Alice's **SSD** grade. |
| F05 | **Missing grade-update authorization** (R3, R4): `update_grade` checks neither role nor course assignment, so students and out-of-course professors can write. | — | — | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | **Confirmed** | `prof_srs` sets SSD grade 16→0. Alice sets her own grade 14→20. |
| F06 | **Unvalidated grade-update payload** (R5, R7): values out of range, booleans, strings, unknown courses, nonexistent students and string `student_id` are stored (new rows are appended). Missing fields and non-object JSON raise 500. | — | — | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | **Confirmed** | 7 invalid payloads accepted with 200 and stored. Missing field → 500 `KeyError`; JSON array → 500 `TypeError`. Booleans were named only in condition C (both runs). |
| F07 | **Student identifier not validated** (R5, R7): `int(student_id)` raises on non-numeric input; `0` and `-1` are accepted. | — | — | ◐ / ◐ | ◐ / ✓ | ✓ / ✓ | **Confirmed** | `/grades/abc` → 500 with `ValueError` text. `/grades/0` and `/grades/-1` → 200 `[]` instead of 400. |
| F08 | **Path traversal** (R6): `download_file` joins the raw `path` onto `MATERIALS_DIR` and calls `send_file` with no containment check. An absolute path replaces the base directory entirely. | — | — | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | **Confirmed** | `../secret.txt`, `sub/../../secret.txt` and an absolute path each disclose a sentinel file outside `materials/`. Run 2 A and B mention only `../`, not absolute paths. |
| F09 | **Exception details disclosed, and every error mapped to 500** (R7): `handle_error` L150 returns `str(exc)` and the class name for every `Exception`, including Werkzeug HTTP errors. | — | — | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | **Confirmed** | A missing file → 500 that leaks the absolute server path. An unknown route → 500 (not 404). A wrong method → 500 (not 405). |
| F10 | **Hard-coded session signing key** `dev-secret-key` (L8) allows session forgery, and therefore forgery of the role and course claims that authorization relies on. | B105 (LOW) | — | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | **Confirmed** | A cookie forged with the key and claiming `role: admin` is accepted by `/me`. Bandit flags the string, not the forgery impact. |
| F11 | **Plaintext hard-coded passwords** in `USERS` (L36–43); `login` compares plaintext. | B106 ×4 (LOW) | — | ✓ / ✓ | ✓ / ✓ | ◐ / ✓ | **Confirmed** (code fact; outside R1–R7) | Code inspection. Run 1 C mentioned it only as an "additional observation". |
| F12 | **`debug=True` on `0.0.0.0`** (L159). The Dockerfile runs this `__main__` block, so the container runs in debug mode. | B201 (HIGH), B104 (MED) | `debug-enabled`, `avoid_app_run_with_bad_host` | ✓ / ✓ | ✓ / ◐ | ✓ / ✓ | **Confirmed** (configuration). RCE via the debugger is **Unverified**. | Code and Dockerfile inspection. `handle_error` intercepts exceptions, so the interactive traceback page is not normally served. |
| F13 | **Session cookie hardening missing**: no explicit `SESSION_COOKIE_SECURE` or `SAMESITE`. | — | — | ✗ / ◐ | ✗ / ✓ | ✗ / ✗ | **Policy-dependent**. The HttpOnly part is a **false positive**. | The observed `Set-Cookie` already has `HttpOnly` (Flask default). `Secure` and `SameSite` are absent. No requirement covers this. |
| F14 | **No login throttling** on `/login`. | — | — | ✓ / ◐ | ✓ / ◐ | ✗ / ✗ | **Policy-dependent** (not in R1–R7) | No limiter in the code. Not tested. |
| F15 | **No CSRF protection** on POST endpoints. | — | — | ✗ / ◐ | ✗ / ◐ | ◐ / ✗ | **Unverified / policy-dependent** | `/grades/update` requires `application/json` (a form post → 415), so a simple cross-site form cannot reach it. Only `/logout` is trivially forgeable. |
| F16 | **Session fixation** (Run 2 A, F-07). | — | — | ✗ / ◐ | ✗ / ✗ | ✗ / ✗ | **False positive** | Flask sessions are signed client-side cookies with no server-side ID to fix. Login re-issues the cookie. The model hedged this claim itself. |
| F17 | **Sessions are not revocable**: a cookie captured before `/logout` is still accepted, and role/courses are copied into the cookie at login (stale privileges). | — | — | ✗ / ✗ | ✗ / ✗ | ✗ / ✗ | **Confirmed behaviour, policy-dependent** (missed by every tool and condition) | A pre-logout cookie replayed after logout → `/me` still returns Alice. |

## Detection summary for the requirement-backed findings (F01–F09)

| Source | ✓ | ◐ | ✗ |
| --- | --- | --- | --- |
| Bandit | 0 | 0 | 9 |
| Semgrep (`p/python`) | 0 | 0 | 9 |
| A (Run 1 / Run 2) | 6 / 6 | 1 / 2 | 2 / 1 |
| B (Run 1 / Run 2) | 6 / 7 | 1 / 1 | 2 / 1 |
| C (Run 1 / Run 2) | 9 / 9 | 0 / 0 | 0 / 0 |

Observations:

- **SAST covers none of F01–F09.** The scanners detect only hard-coded values and run configuration (F10–F12). Semgrep's `p/python` ruleset did not flag the `send_file` traversal (F08), and neither did Bandit.
- **Code alone (A) already reveals missing authentication and ownership checks** (F01, F02, F05) and the path traversal. What A cannot know is the *policy* for staff, so F03 and F04 are missed or left as open questions.
- **Context (B) changed little.** It named professor course assignments as a concern (F04 ◐, Run 2), but the model still treated the professor policy as unknown. In Run 2 it even assumed professors may read profiles, which is the opposite of R3.
- **Explicit requirements (C) were needed for the missing-control findings F03 and F04** and for precise validation rules (booleans, positive identifiers). C also *dropped* findings outside R1–R7, such as throttling and cookie flags. This is a narrowing effect of the requirements.
- **Incorrect claims.** F16 is a false positive (session fixation does not apply to client-side Flask sessions). The F13 HttpOnly claim is contradicted by the observed cookie. No condition invented a vulnerability that the code does not support.
- **Missed by everything:** F17 (non-revocable sessions and privileges cached in the cookie).

## Protocol notes

- **Run 2 C prompt deviation.** [`Luis-C-prompt.md`](../discovery/Luis-C-prompt.md) contains extra text copied from the assignment PDF (the Part III / Section 7 instructions), and its R7 requirement is cut off mid-sentence. That is why [`Luis-C-response.md`](../discovery/Luis-C-response.md) contains its own "consolidated table" and marks every finding "Confirmed" without evidence. Those self-assigned statuses were ignored. Only the findings section was used. Run 1 C is a clean replication and reached the same F01–F09 coverage.
- The model name, version and settings for each run should be recorded in `evidence/discovery/model.md` (not yet present).
- Statuses above come from code reasoning plus the executable reproduction, never from asking the model to grade itself.
