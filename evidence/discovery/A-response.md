# Static Security Review — Baseline Secure Coding API

File reviewed: `baseline_secure_coding_api.py` (159 lines)\
Method: Static source inspection only\
Scope: Authentication, authorization, input validation, file access, session integrity, error handling, and deployment configuration.

No code was executed, no external sources were consulted, and no vulnerabilities were dynamically verified.

## 1. Findings summary

The review identified 9 potential security findings, including several directly evidenced missing controls. Severity estimates assume the API is accessible to untrusted clients and handles data requiring protection.

| ID     | Finding                                   | Location                                 | Estimated severity | Confidence |
| ------ | ----------------------------------------- | ---------------------------------------- | ------------------ | ---------- |
| SEC-01 | Arbitrary file read via path traversal    | `download_file()`, 144–148               | Critical           | High       |
| SEC-02 | Unauthenticated grade modification        | `update_grade()`, 128–142                | Critical           | High       |
| SEC-03 | Missing authorization for student records | `get_profile()`, `get_grades()`, 115–126 | High               | High       |
| SEC-04 | Hardcoded Flask session-signing secret    | Lines 7–8, 91–94                         | High               | High       |
| SEC-05 | Hardcoded plaintext account credentials   | Lines 27–42, 82–89                       | High\*             | High       |
| SEC-06 | Debug mode exposed on all interfaces      | Lines 158–159                            | High\*             | High       |
| SEC-07 | Missing grade-update input validation     | `update_grade()`, 130–140                | Medium             | High       |
| SEC-08 | Exception details disclosed to clients    | `handle_error()`, 150–155                | Medium             | High       |
| SEC-09 | No application-level login throttling     | `login()`, 82–96                         | Medium\*           | Medium     |

\*Severity depends significantly on whether this demonstration application is deployed, who can reach it, and whether additional security controls exist outside the reviewed file.

## 2. Supporting explanations

### SEC-01 — Arbitrary file read via path traversal

Location: `download_file()`, lines 144–148.&#x20;

baseline_secure_coding_api.py



Demonstrated code facts: The endpoint reads the attacker-controlled `path` query parameter, combines it with `MATERIALS_DIR` using `pathlib.Path`, and passes the resulting path to `flask.send_file()`.

Data flow: `GET /files?path=...` → `request.args.get()` → `MATERIALS_DIR / raw_path` → `flask.send_file(target)`.

Root cause: No containment check ensures that the resolved file remains inside `MATERIALS_DIR`. Parent-directory components and absolute paths can escape the intended directory.

Preconditions and impact: If an attacker can reach `/files` and the server process can read the targeted file, the attacker may retrieve files outside the materials directory, including application source or other sensitive files.

Proposed test: Place a harmless sentinel file outside `MATERIALS_DIR`. Request it using a relative traversal path such as `../sentinel.txt`, and verify whether the response contains its contents. Separately test an absolute path to a controlled fixture.

Assumptions and confidence: High confidence in the missing containment control. Successful exploitation depends on filesystem permissions, path handling, and deployment configuration. The assumption is that only designated materials should be downloadable.

### SEC-02 — Unauthenticated grade modification

Location: `update_grade()`, lines 128–142.&#x20;

baseline_secure_coding_api.py



Demonstrated code facts: The endpoint accepts JSON fields `student_id`, `course_id`, and `grade`. It then updates a matching record or appends a new record. No session, identity, role, or course-ownership check appears in the function.

Data flow: Attacker-supplied JSON → `get_json()` → `find_grade()` → update `GRADES` or append a new record.

Root cause: Missing authentication and object-level authorization before modifying grade data.

Preconditions and impact: Any caller who can access the endpoint may change or create grades. If grades represent authoritative academic records, this compromises their integrity.

Proposed test: Without logging in, submit a grade update for an existing student and course. Retrieve the grade afterward and check whether the modification persisted. Repeat while authenticated as a student.

Assumptions and confidence: High confidence in the absence of access control. The expected policy—that only appropriately authorized staff can change grades—is inferred, not explicitly stated in the source.

### SEC-03 — Missing authorization for student records

Locations: `get_profile()`, lines 115–120; `get_grades()`, lines 122–126.&#x20;

baseline_secure_coding_api.py



Demonstrated code facts: Both endpoints accept a student identifier from the URL and retrieve the matching record without checking the caller's identity or permissions.

Data flow: Attacker-controlled URL parameter → `int(student_id)` → `STUDENT_PROFILES` lookup or `GRADES` filtering → JSON response.

Root cause: No authentication or object-level access control. The supplied student identifier determines which record is returned.

Preconditions and impact: Any client with endpoint access can request student identifiers. The profile endpoint exposes names, email addresses, and programme information; the grades endpoint exposes academic results. Predictable numeric identifiers facilitate enumeration.

Proposed test: Request records for students `1001` and `1002` without authenticating. Repeat while authenticated as Alice and request Bob's records. Check whether either endpoint refuses access.

Assumptions and confidence: High confidence in unrestricted retrieval. Whether these records must be private is a policy assumption, although student profiles and grades are normally access-controlled.

### SEC-04 — Hardcoded Flask session-signing secret

Locations: Lines 7–8 and 91–94.&#x20;

baseline_secure_coding_api.py

baseline_secure_coding_api.py



Demonstrated code facts: The application sets `SECRET_KEY` to the fixed string `dev-secret-key`. Successful login stores username, role, student ID, and courses in the Flask session.

Root cause: A predictable, hardcoded signing secret undermines the integrity guarantee of standard Flask signed client-side sessions.

Preconditions and impact: Assuming standard Flask session behavior and that this key is used in deployment, a party who knows the secret can generate valid signed session data. This can enable session impersonation or role-claim manipulation.

The visible `/me` endpoint would reflect forged identity fields. However, the reviewed grade and profile endpoints do not use session authorization, so additional privilege escalation through those endpoints is not demonstrated.

Proposed test: In an isolated test environment, construct a test session cookie using the configured secret and a different username and role. Request `/me` without logging in and inspect the returned identity.

Assumptions and confidence: High confidence in the exposed secret and its implications under standard Flask session handling. The broader impact depends on other code trusting session claims.

### SEC-05 — Hardcoded plaintext account credentials

Locations: Lines 27–42 and 82–89.&#x20;

baseline_secure_coding_api.py

baseline_secure_coding_api.py



Demonstrated code facts: Four accounts have passwords stored directly as plaintext in source code. The login function compares the supplied password directly with `user.password`.

Root cause: Authentication secrets are embedded in application source, and passwords are not stored as salted password hashes.

Preconditions and impact: Anyone who obtains these credentials, including through source exposure, can authenticate as the corresponding account. A source leak therefore exposes all seeded passwords, including administrator credentials.

Proposed test: Authenticate using one of the credentials declared in `USERS`. Verify the account role returned by `/me`.

Assumptions and confidence: High confidence that the implementation uses plaintext passwords. These may be intentional demonstration accounts. Severity is substantially lower if they are exclusively disposable test credentials in an isolated environment.

### SEC-06 — Debug mode exposed on all interfaces

Location: Lines 158–159.&#x20;

baseline_secure_coding_api.py



Demonstrated code facts: When the file is launched directly, Flask runs with `debug=True` and `host="0.0.0.0"`.

Root cause: The application enables development debugging while binding to all network interfaces.

Preconditions and impact: If directly executed in a network-accessible environment, development debugging may expose diagnostic information and an interactive debugger. Under certain conditions, debugger access can lead to remote code execution.

This does not establish that an interactive debugger is reachable or that its protections can be bypassed.

Proposed test: In an isolated environment, launch the application through its main entry point, trigger a controlled exception, and check whether an external client can see debugger functionality or sensitive diagnostic details.

Assumptions and confidence: High confidence in the configuration. Actual exploitability depends on the launch method, network exposure, debugger protections, and deployment environment.

### SEC-07 — Missing grade-update input validation

Location: `update_grade()`, lines 130–140.&#x20;

baseline_secure_coding_api.py



Demonstrated code facts: JSON fields are used without explicit type checks, permitted-value validation, or referential-integrity checks. The function can also create records for previously unknown student/course combinations.

Root cause: Unvalidated request data reaches the application's grade store directly.

Preconditions and impact: A caller may submit negative grades, strings, unexpected JSON structures, or nonexistent identifiers. These values could corrupt records or create inconsistent representations.

For example, a JSON string student ID and a numeric student ID will not compare equally in the current lookup logic.

Proposed test: Submit cases containing `"grade": -5`, `"grade": "invalid"`, `"student_id": "1001"`, and nonexistent identifiers. Inspect whether they are accepted and how subsequent grade retrieval behaves.

Assumptions and confidence: High confidence in missing validation. Permitted grade ranges and legitimate student/course combinations are unspecified; these must be defined before judging which particular values should be rejected.

### SEC-08 — Exception details disclosed to clients

Location: `handle_error()`, lines 150–155.&#x20;

baseline_secure_coding_api.py



Demonstrated code facts: A global exception handler returns `str(exc)` and the exception class name in the HTTP response, using status code 500.

Root cause: Internal exception information is returned directly to callers rather than being separated from client-facing error messages. The broad handler also treats otherwise expected HTTP errors as server errors.

Preconditions and impact: An attacker capable of triggering errors may receive implementation details, including filesystem paths or error-specific diagnostics, depending on the exception.

Proposed test: Request a nonexistent file and submit a nonnumeric student ID. Inspect whether the responses reveal internal paths, exception types, or details not intended for clients.

Assumptions and confidence: High confidence in the information-return behavior. The sensitivity of the exposed details varies by exception; disclosure of stack traces by this handler is not demonstrated.

### SEC-09 — No application-level login throttling

Location: `login()`, lines 82–96.&#x20;

baseline_secure_coding_api.py



Demonstrated code facts: The login endpoint performs a direct credential comparison and returns a failure response for incorrect credentials. There is no visible request-rate limit, failure counter, or temporary lockout.

Root cause: The reviewed application does not implement protections against repeated authentication attempts.

Preconditions and impact: If `/login` is publicly accessible and no external rate limiting exists, attackers may repeatedly attempt passwords for known usernames, potentially compromising weak credentials.

Proposed test: In an isolated test environment, issue a controlled sequence of invalid login attempts for a test account. Check whether the application restricts further attempts or introduces any protective response.

Assumptions and confidence: Medium confidence as a system-level vulnerability. Missing application-level throttling is demonstrated, but upstream gateway or infrastructure protections are unknown.

## 3. Cross-cutting observations

The most significant code-level issue is the absence of consistent trust-boundary enforcement. The application establishes sessions during login, but the endpoints that read and modify student information do not consult those sessions.

Several issues also interact:

- SEC-01 and SEC-04: If file traversal exposes application source, it can reveal the static session-signing key.
- SEC-01 and SEC-05: Source exposure can disclose account credentials.
- SEC-02 and SEC-07: Unauthenticated writes combined with missing validation allow both unauthorized and malformed grade changes.
- SEC-06 and SEC-08: Development debugging and verbose error responses can increase the information available to an attacker, although their exact effects depend on deployment.

## 4. Suggested validation priority

| Priority | Findings               | Validation objective                                                                               |
| -------- | ---------------------- | -------------------------------------------------------------------------------------------------- |
| P0       | SEC-01, SEC-02         | Establish whether unauthenticated clients can read outside the materials directory or alter grades |
| P1       | SEC-03, SEC-04, SEC-06 | Verify record access restrictions, session integrity, and deployed debugger exposure               |
| P2       | SEC-05, SEC-07         | Establish credential handling requirements and accepted data constraints                           |
| P3       | SEC-08, SEC-09         | Assess error information disclosure and protection against repeated login attempts                 |

## 5. Review limitations and conclusion

This review establishes specific code facts but does not establish runtime exploitability. The source does not specify the intended authorization policy, network topology, reverse-proxy controls, permitted grade ranges, or whether the application is restricted to a teaching environment.

Overall assessment: The source contains multiple high-confidence security weaknesses, particularly around file access, grade modification, and student-record access. If exposed to untrusted users while managing real data, these would represent substantial confidentiality and integrity risks.

All nine findings remain statically identified and unverified by execution. The absence of additional findings is not evidence that the application is secure. No patches were generated.