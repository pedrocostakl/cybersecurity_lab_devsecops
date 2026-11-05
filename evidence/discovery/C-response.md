# Static Security Review — Academic Services REST API

Scope: `baseline_secure_coding_api(2).py`, lines 1–159.

Method: Static inspection only. No code execution, external tools, web browsing, or published solutions were used. Findings are assessed against the supplied requirements R1–R7.

## 1. Executive summary

# 6

High / Critical

# 2

Medium

# 2

Conditional

The review identifies 10 potential security findings, including several directly demonstrable from the source.

The most significant issues are missing authentication and record-level authorization, unrestricted grade modifications, and file path traversal. The application also lacks required input validation and exposes implementation errors.

Severity is a qualitative assessment, not an exploitability measurement.

## 2. Concise findings table

| ID   | Finding                                                    | Affected location                                                           | Severity    | Requirement |
| ---- | ---------------------------------------------------------- | --------------------------------------------------------------------------- | ----------- | ----------- |
| F-01 | Missing authentication on protected endpoints              | `get_profile`, `get_grades`, `update_grade`, `download_file`; lines 115–148 | Critical    | R1, R7      |
| F-02 | Broken profile-level authorization (IDOR)                  | `get_profile`; 115–120                                                      | High        | R2–R4       |
| F-03 | Unrestricted grade disclosure and missing result filtering | `get_grades`; 122–126                                                       | High        | R2–R4       |
| F-04 | Unauthorized grade creation and modification               | `update_grade`; 128–142                                                     | Critical    | R3, R4, R7  |
| F-05 | Directory traversal and arbitrary readable-file access     | `download_file`; 144–148                                                    | High        | R6          |
| F-06 | Missing student identifier validation                      | `get_profile`, `get_grades`; 117, 124                                       | Medium      | R5, R7      |
| F-07 | Unvalidated grade-update payload                           | `update_grade`; 130–140                                                     | High        | R5, R7      |
| F-08 | Information disclosure through global exception handler    | `handle_error`; 150–155                                                     | Medium      | R7          |
| F-09 | Predictable session-signing secret                         | Configuration, `login`, `me`; 8, 91–94, 103–112                             | Conditional | R1, R4      |
| F-10 | Debug mode enabled on all interfaces                       | Application startup; 158–159                                                | Conditional | R7          |

## 3. Supporting analysis

### F-01 — Missing authentication on protected endpoints

Demonstrated facts: None of the four protected endpoint handlers checks `flask.session` or otherwise verifies an authenticated user. Login stores session information (lines 91–94), but the protected handlers do not consume it.

Attack path: An unauthenticated client directly requests `/students/1001/profile`, `/grades/1001`, `/grades/update`, or `/files?path=srs-summary.txt`. The relevant handler accesses records or files without first verifying the requester.

Root cause: Authentication is implemented during login but is not enforced on protected requests.

Preconditions and impact: An attacker only needs network access to the API. They may read student information, read grades, modify grades, or download files without logging in.

Proposed test: Using a client with no session cookie, request each protected endpoint with otherwise valid inputs. Expect HTTP 401 and no data disclosure or mutation.

Assumptions: R1 explicitly requires authentication for these operations. No external authentication middleware is shown.

Confidence: High — direct source evidence.&#x20;

baseline_secure_coding_api(2).py



### F-02 — Broken profile-level authorization (IDOR)

Demonstrated facts: `get_profile` converts the URL identifier to an integer and looks it up directly in `STUDENT_PROFILES`. It does not compare the identifier with the authenticated student's assigned ID or check the requester's role.

Attack path: Student Alice requests `/students/1002/profile`. The lookup selects Bob's profile and returns his name, email, and program. A professor can use the same endpoint.

Root cause: A valid record identifier is treated as sufficient authority to retrieve the record.

Preconditions and impact: The target profile exists and the requester knows or guesses its identifier. This exposes other students' personal information.

Proposed test: Authenticate as Alice and request profile `1002`; then authenticate as `prof_srs` and request profile `1001`. Both should return HTTP 403. An administrator should be allowed.

Assumptions: Profile ownership and professor restrictions are explicitly defined by R2 and R3.

Confidence: High — authorization checks are absent.&#x20;

baseline_secure_coding_api(2).py



### F-03 — Unrestricted grade disclosure and missing result filtering

Demonstrated facts: `get_grades` filters records only by `student_id`, not by requester identity or assigned courses. It also returns an empty list with HTTP 200 when no records match.

Attack path: A student can replace their own identifier with another student's. Professor `prof_srs`, assigned only to SRS, can request `/grades/1001` and receive both Alice's SRS and SSD grades.

Root cause: The query's student identifier determines the entire response. No per-record authorization filter is applied.

Preconditions and impact: Target records exist. Unauthorized student grades may be disclosed, including grades outside a professor's course assignment.

Proposed test: Authenticate as `prof_srs`, request `/grades/1001`, and verify that only the SRS record appears. Authenticate as Bob and request `/grades/1001`; expect HTTP 403. Verify that requests with no permitted records are denied rather than returning an empty successful response.

Assumptions: R4 requires permitted-only list results and denial when no permitted records exist.

Confidence: High.&#x20;

baseline_secure_coding_api(2).py



### F-04 — Unauthorized grade creation and modification

Demonstrated facts: `update_grade` does not inspect the session, role, student ownership, or professor course assignments. It updates a matching record or appends a new one.

Attack path: An attacker submits:

```
{
  "student_id": 1001,
  "course_id": "SSD",
  "grade": 20
}
```

`find_grade` finds the corresponding row and `row["grade"] = grade` overwrites its value. This operation is possible without administrator or assigned-professor authorization.

Root cause: The update operation lacks both role-based and record-level authorization.

Preconditions and impact: The attacker can submit an HTTP POST containing JSON. This allows unauthorized manipulation of academic records and compromises grade integrity.

Proposed test: Authenticate as `prof_srs` and attempt to update an SSD grade. Repeat as a student. Both requests should return HTTP 403, with the stored grade unchanged. Verify that an administrator can perform the valid update.

Assumptions: R3 permits grade updates only by administrators and professors assigned to the relevant course.

Confidence: High.&#x20;

baseline_secure_coding_api(2).py



### F-05 — Directory traversal and arbitrary file access

Demonstrated facts: The `path` query parameter is appended directly to `MATERIALS_DIR`:

```
target = MATERIALS_DIR / raw_pathreturn flask.send_file(target)
```

There is no containment or resolved-path validation.

Attack path: An attacker supplies a traversal value such as `../outside.txt` or an absolute filesystem path. Path construction can reference a file outside the materials directory, and `send_file` attempts to serve that target.

Root cause: Untrusted file paths are used without enforcing the permitted directory boundary.

Preconditions and impact: The target exists and is readable by the application process. The attacker may download files outside `materials`, potentially including configuration files or other sensitive data.

Proposed test: Create a harmless sentinel file outside the materials directory in an isolated test environment. Request it using `../` traversal and an absolute path. Both requests should be rejected without returning its contents.

Assumptions: No external filesystem isolation is assumed. Exact readable files depend on deployment permissions.

Confidence: High for missing containment; actual exposure depends on filesystem access.&#x20;

baseline_secure_coding_api(2).py



### F-06 — Missing student identifier validation

Demonstrated facts: Both `get_profile` and `get_grades` convert URL parameters with `int(student_id)` without checking whether the resulting value is positive or handling conversion failures.

Attack path: `/grades/-1` is accepted and returns an empty list with HTTP 200. `/grades/abc` causes a `ValueError`, which is processed by the global exception handler.

Root cause: Integer conversion is used instead of complete validation of a positive integer identifier.

Preconditions and impact: Any requester can submit malformed identifiers. The result is inconsistent rejection behavior and potentially internal error disclosure.

Proposed test: Request profile and grade endpoints using `0`, `-1`, `abc`, and a valid identifier. Invalid identifiers should produce appropriate 4xx responses without implementation details.

Assumptions: R5 applies to student identifiers received through URLs as well as JSON input.

Confidence: High.&#x20;

baseline_secure_coding_api(2).py



### F-07 — Unvalidated grade-update payload

Demonstrated facts: `update_grade` reads JSON fields directly and writes their values without validating types, required fields, student existence, known courses, or grade range. `find_grade` only performs equality comparisons against existing rows.

Attack path: A client sends a valid JSON object containing an invalid grade, unknown course, or nonexistent student. The handler can update an existing record or append an invalid record.

Root cause: No input schema or semantic validation precedes mutation.

Preconditions and impact: Access to the update endpoint, currently unauthenticated. Invalid academic data can be persisted in memory. Missing fields or malformed JSON may produce server errors.

Proposed test: Submit the following independent cases and verify rejection without mutation:

| Invalid input                       | Expected result |
| ----------------------------------- | --------------- |
| `"grade": -1`                       | 4xx, unchanged  |
| `"grade": 21`                       | 4xx, unchanged  |
| `"grade": true`                     | 4xx, unchanged  |
| `"grade": "18"`                     | 4xx, unchanged  |
| `"course_id": "UNKNOWN"`            | 4xx, unchanged  |
| `"student_id": 9999`                | 4xx, unchanged  |
| Missing `grade`                     | 4xx, unchanged  |
| JSON array, null, or malformed JSON | 4xx, unchanged  |

Assumptions: The existing student identifiers and known course identifiers are those explicitly provided by the exercise. Floating-point numeric grades within range are not prohibited by R5.

Confidence: High.&#x20;

baseline_secure_coding_api(2).py



### F-08 — Information disclosure through global exception handler

Demonstrated facts: `handle_error` catches every `Exception` and returns its string representation and Python class name using HTTP 500, regardless of the underlying error.

Attack path: An invalid identifier triggers `ValueError`; a missing file may trigger `FileNotFoundError`; malformed requests may produce Flask HTTP exceptions. The handler exposes error details and replaces the intended status with 500.

Root cause: Broad exception interception without separating expected client errors from unexpected server failures, combined with direct serialization of exception messages.

Preconditions and impact: An attacker can submit invalid requests. Responses may expose internal filesystem paths, implementation details, and exception types. Valid HTTP 4xx errors may be incorrectly converted to 500.

Proposed test: Request `/grades/notanumber`, a nonexistent route, and a missing file. Verify appropriate 4xx responses without internal paths, exception class names, or tracebacks.

Assumptions: Exact messages depend on the Flask and Python versions.

Confidence: High for the incorrect handling; medium for particular disclosure contents.&#x20;

baseline_secure_coding_api(2).py



### F-09 — Predictable session-signing secret

Demonstrated facts: The application configures a fixed string, `dev-secret-key`, as its `SECRET_KEY`. Login writes identity and role information to Flask sessions, and `/me` reads it back.

Potential attack path: If an attacker knows the signing secret, they may be able to produce a valid signed Flask session cookie containing altered identity, role, or course claims. `/me` would then reflect the supplied claims.

Root cause: A static, source-visible session-signing secret is used as an authentication trust boundary.

Preconditions and impact: The attacker must know or recover the secret and use a compatible session-signing format. The immediate demonstrated concern is session-identity forgery; privileged operations already lack authorization checks, so additional impact through those operations is not established by this source.

Proposed test: In an isolated test environment, construct a session cookie using the configured secret and altered user claims. Verify whether `/me` accepts it as authenticated session state.

Assumptions: This assessment relies on Flask's standard signed-cookie session behavior. The exercise does not explicitly require secure secret management.

Confidence: High for the hardcoded secret; medium for practical exploitability and relevance beyond `/me`.&#x20;

baseline_secure_coding_api(2).py

baseline_secure_coding_api(2).py



### F-10 — Debug mode enabled on all interfaces

Demonstrated facts: The application starts using:

```
app.run(debug=True, host="0.0.0.0", port=5001)
```

Potential attack path: If the development server is reachable by untrusted clients and an exception reaches the interactive debugger, sensitive diagnostic information or dangerous debugger functionality may become accessible.

Root cause: Debug configuration is enabled in a network-listening application.

Preconditions and impact: Deployment must use this startup path, the listening port must be reachable, and an exception must bypass or otherwise reach debugger handling. The global exception handler may prevent ordinary request exceptions from doing so.

Proposed test: In an isolated environment, verify the active debugger configuration and whether unexpected exceptions expose debug output to an external test client. Do not expose a development debugger publicly.

Assumptions: R7 prohibits exposing implementation details. The request does not establish actual deployment configuration.

Confidence: High for debug configuration; low for externally exploitable debugger access.&#x20;

baseline_secure_coding_api(2).py



## 4. Requirements coverage

| Requirement                 | Assessment | Main findings                |
| --------------------------- | ---------- | ---------------------------- |
| R1 — Authentication         | Violated   | F-01                         |
| R2 — Student privacy        | Violated   | F-02, F-03                   |
| R3 — Academic staff scope   | Violated   | F-02, F-03, F-04             |
| R4 — Complete authorization | Violated   | F-02, F-03, F-04             |
| R5 — Input validation       | Violated   | F-06, F-07                   |
| R6 — File access            | Violated   | F-05                         |
| R7 — Error handling         | Violated   | F-01, F-04, F-06, F-07, F-08 |

The file-download endpoint's session requirement is covered by F-01; its directory boundary is covered by F-05.

## 5. Additional observations and limitations

The application also stores demonstration user passwords in plaintext in the source (lines 36–43). This creates a credential-disclosure concern if those credentials are deployed unchanged or the source becomes accessible to untrusted parties. However, the exercise explicitly describes a small teaching environment and does not require password hashing, so this is not classified as a separate R1–R7 violation.

Likewise, no CSRF protection is visible on state-changing endpoints. Whether that creates an independently exploitable browser-based attack depends on session-cookie behavior, deployment context, and accepted request formats. The missing authorization checks already establish more direct update risks.

The following distinctions are important:

- Demonstrated code facts: Missing checks, unrestricted record selection and mutation, unsanitized path construction, missing validation, broad exception handling, fixed signing secret, and enabled debug mode.
- Inferred or conditional effects: Which external files can actually be read, whether session forgery is feasible for a given attacker, and whether the development debugger is externally reachable.
- Not assessed: Infrastructure controls, reverse proxies, client behavior, dependencies, operational access restrictions, and runtime behavior not established by the supplied source.

## 6. Review conclusion

The highest-priority validation targets are F-01, F-04, F-05, F-02, and F-03, because they concern fundamental authentication, academic-record integrity, data confidentiality, and filesystem boundaries.

F-06 through F-08 concern malformed inputs, invalid state changes, and information leakage. F-09 and F-10 warrant configuration review, but their real-world exploitability cannot be concluded from this file alone.

Overall assessment: The source contains multiple directly observable violations of the stated security requirements. These findings are static-review claims, not dynamically verified exploits. No tests were executed and no patches were generated.

The review is limited to the supplied source; neither identified vulnerabilities nor an absence of additional findings establishes the complete security state of the deployed application.