# Static Security Review — Academic Services REST API

Scope: `baseline_secure_coding_api(1).py` (159 lines)

Method: Static source inspection only. No code execution, testing, external research, or tools used. Findings are based exclusively on the supplied application source and context.

Overall assessment: The source contains several high-risk security weaknesses, particularly in authorization, grade integrity, file access, and session configuration. The strongest findings follow directly from missing checks in the request handlers. Their exploitability in a deployed environment remains untested.

## 1. Findings summary

| ID     | Finding                                           | Affected location                      | Severity\*           | Confidence |
| ------ | ------------------------------------------------- | -------------------------------------- | -------------------- | ---------- |
| SEC-01 | Unauthenticated grade modification                | `update_grade()`, L128–142             | Critical             | High       |
| SEC-02 | Unrestricted student profile access               | `get_profile()`, L115–120              | High                 | High       |
| SEC-03 | Unrestricted grade retrieval                      | `get_grades()`, L122–126               | High                 | High       |
| SEC-04 | Directory traversal and arbitrary file disclosure | `download_file()`, L144–148            | Critical             | High       |
| SEC-05 | Hardcoded session signing secret                  | Configuration, L7–8; `login()`, L91–94 | High                 | High       |
| SEC-06 | Hardcoded plaintext account credentials           | `USERS`, L27–43; `login()`, L87–89     | Medium               | High       |
| SEC-07 | Missing grade input and integrity validation      | `update_grade()`, L130–140             | High                 | High       |
| SEC-08 | Exception information disclosure                  | `handle_error()`, L150–155             | Medium               | High       |
| SEC-09 | Debug server bound to all interfaces              | Application startup, L158–159          | High (conditional)   | High       |
| SEC-10 | No application-level login throttling             | `login()`, L82–96                      | Medium (conditional) | Medium     |

Severity is a preliminary risk assessment, not a verified exploitability rating. It assumes the API is reachable by potentially untrusted users and that student data and grades require access restrictions.

## 2. Supporting explanations

### SEC-01 — Unauthenticated grade modification

Location: `update_grade()`, lines 128–142.&#x20;

baseline_secure_coding_api(1).py



Demonstrated facts: The endpoint accepts `student_id`, `course_id`, and `grade` from a JSON request. It locates an existing record using `find_grade()` and either changes the grade or inserts a new record. No session, identity, or role check occurs.

Attacker-controlled flow: `POST /grades/update` → JSON body → `find_grade(student_id, course_id)` → mutation of `GRADES`.

Root cause: Missing authentication and object-level authorization. The supplied professor-course assignments are not consulted.

Preconditions and impact: A client able to reach the endpoint can submit grade changes without authenticating. This permits unauthorized modification or creation of academic records.

Proposed test: Submit a grade update in a fresh session without logging in. Retrieve the corresponding grade afterward and check whether the change persisted.

Assumptions and uncertainty: The exact roles permitted to modify grades are unspecified. Restricting updates to assigned professors or administrators is a reasonable inferred policy, not a demonstrated requirement.

Confidence: High for the missing checks and mutation path.

### SEC-02 — Unrestricted student profile access

Location: `get_profile()`, lines 115–120.&#x20;

baseline_secure_coding_api(1).py



Demonstrated facts: The handler converts the URL parameter to an integer and retrieves a student profile directly from `STUDENT_PROFILES`. It never checks `flask.session` or the requesting user's identity.

Attacker-controlled flow: `GET /students/<student_id>/profile` → supplied student ID → dictionary lookup → JSON response.

Root cause: Missing authentication and object-level authorization, potentially an insecure direct object reference (IDOR).

Preconditions and impact: Any reachable client can request known student identifiers and obtain names, email addresses, and academic program information.

Proposed test: Request student 1002's profile while unauthenticated, then repeat while authenticated as student 1001.

Assumptions and uncertainty: Profile confidentiality is inferred from the multi-user academic context. The source does not specify whether some profile attributes are intended to be public.

Confidence: High.

### SEC-03 — Unrestricted grade retrieval

Location: `get_grades()`, lines 122–126.&#x20;

baseline_secure_coding_api(1).py



Demonstrated facts: The endpoint returns every grade record matching the user-supplied student identifier. It does not examine the current session or assigned courses.

Attacker-controlled flow: `GET /grades/<student_id>` → student ID → filter over `GRADES` → JSON response.

Root cause: Missing authentication and record-level authorization.

Preconditions and impact: A client can retrieve another student's grades without establishing an authorized relationship to that student or course.

Proposed test: Request `/grades/1002` without authentication and as student 1001. Determine whether both requests return student 1002's records.

Assumptions and uncertainty: Grades are assumed to be confidential educational records. The precise professor and administrator read policies are unspecified.

Confidence: High.

### SEC-04 — Directory traversal and arbitrary file disclosure

Location: `download_file()`, lines 144–148.&#x20;

baseline_secure_coding_api(1).py



Demonstrated facts: The handler combines an attacker-controlled `path` parameter with `MATERIALS_DIR` and passes the result directly to `flask.send_file()`.

Attacker-controlled flow: `GET /files?path=...` → `raw_path` → `MATERIALS_DIR / raw_path` → `send_file(target)`.

Root cause: No validation that the resolved file remains within the designated materials directory. Filesystem parent components and absolute paths are not rejected. Authentication is also absent.

Preconditions and impact: If the process can read a targeted file, an attacker may be able to download files outside `materials`, including application source and configuration files. Source disclosure could compound SEC-05 and SEC-06.

Proposed test: Place a harmless marker file outside `materials` in a controlled test environment. Request it using a parent-directory path and verify whether its content is returned. Repeat with an absolute path.

Assumptions and uncertainty: Actual file exposure depends on the runtime filesystem and process permissions. The material-directory boundary is inferred from the specified storage location.

Confidence: High for the traversal condition; actual accessible files are unverified.

### SEC-05 — Hardcoded session signing secret

Location: Configuration at line 8, with session values assigned in `login()` at lines 91–94.&#x20;

baseline_secure_coding_api(1).py



Demonstrated facts: `SECRET_KEY` contains a fixed literal value. Login stores the username, role, student ID, and assigned courses in the Flask session.

Relevant trust boundary: Under Flask's normal signed client-side session behavior, knowledge of the signing key can permit construction of apparently valid session cookies.

Root cause: A static, source-embedded signing secret rather than a confidential, deployment-specific secret.

Preconditions and impact: An attacker must learn the secret and be able to submit a crafted cookie. Session impersonation or role-claim manipulation may then be possible. The file-disclosure weakness provides a potential route to learning the key.

Proposed test: In an isolated test deployment, construct a session cookie using the known key and altered identity fields. Submit it to `/me` and observe whether those fields are accepted.

Assumptions and uncertainty: Actual forging depends on the deployed Flask session configuration. The existing privileged endpoints do not currently consult session roles, so an additional role-based authorization bypass is not demonstrated.

Confidence: High for the configuration weakness; conditional for further exploitation.

### SEC-06 — Hardcoded plaintext account credentials

Location: `User` and `USERS`, lines 27–43; credential comparison at lines 87–89.&#x20;

baseline_secure_coding_api(1).py



Demonstrated facts: The source contains plaintext passwords for student, professor, and administrator accounts. Authentication compares the submitted password directly with the stored string.

Attacker-controlled flow: `POST /login` → supplied credentials → `USERS` lookup → plaintext equality comparison → session assignment.

Root cause: Credentials are embedded in source code rather than managed as protected authentication secrets.

Preconditions and impact: Someone who obtains the source can learn the predefined credentials and potentially log in as those accounts.

Proposed test: In an isolated deployment, authenticate using one of the source-defined credential pairs and verify that `/me` reports the corresponding identity.

Assumptions and uncertainty: The application is explicitly a teaching environment. These may be intentionally shared demonstration accounts. The risk is conditional on whether they are expected to represent independently trusted users.

Confidence: High.

### SEC-07 — Missing grade input and integrity validation

Location: `update_grade()`, lines 130–140.&#x20;

baseline_secure_coding_api(1).py



Demonstrated facts: The endpoint accepts JSON values without checking their types, permitted ranges, student existence, or course existence. It can append records for previously unknown student/course combinations.

Attacker-controlled flow: JSON body → direct extraction of fields → grade lookup → insertion or update.

Root cause: Missing request-schema validation and academic-record consistency checks.

Preconditions and impact: Any caller able to reach the endpoint can submit malformed, inconsistent, or unexpected grade values. These could corrupt records or cause problems for downstream consumers.

Proposed test: Submit a nonnumeric grade, a negative grade, an unknown student ID, and an unknown course ID. Inspect whether the API accepts them and whether they appear in subsequent retrievals.

Assumptions and uncertainty: The valid grade scale and allowed course/student relationships are not specified. Rejecting nonnumeric or nonexistent identifiers is a proposed integrity requirement, not an established policy.

Confidence: High for missing validation; medium for policy-specific impact.

### SEC-08 — Exception information disclosure

Location: `handle_error()`, lines 150–155.&#x20;

baseline_secure_coding_api(1).py



Demonstrated facts: The global exception handler returns `str(exc)` and the exception class name to the requester, always with HTTP status 500.

Attacker-controlled flow: Malformed request → exception → `handle_error()` → error details in JSON response.

Root cause: Internal exception information is exposed to clients. The broad handler also changes ordinary HTTP exception statuses into 500 responses.

Preconditions and impact: A remotely triggered exception can reveal implementation details, possibly including filesystem paths. Such information may assist further probing.

Proposed test: Submit a nonnumeric student ID or request a nonexistent file. Examine the response for internal exception messages, class names, and unexpected HTTP status codes.

Assumptions and uncertainty: The exact information exposed depends on the exception and runtime. This handler itself does not explicitly return stack traces.

Confidence: High.

### SEC-09 — Debug server bound to all interfaces

Location: Application startup, lines 158–159.&#x20;

baseline_secure_coding_api(1).py



Demonstrated facts: When executed as the main script, the application calls `app.run(debug=True, host="0.0.0.0", port=5001)`.

Relevant execution path: Application startup → Flask development server → debug mode with a network-facing bind address.

Root cause: A debug configuration that is potentially accessible beyond the local machine.

Preconditions and impact: The program must be run directly, and network connectivity must permit access. Depending on Flask/Werkzeug behavior and exception handling, debugger functionality could introduce substantial security risk.

Proposed test: In a disposable, network-isolated environment, inspect the development server's debug behavior and determine whether remote clients can reach diagnostic functionality. Do not attempt this against a live deployment.

Assumptions and uncertainty: The deployment mechanism is unknown. The custom exception handler may prevent ordinary exceptions from reaching the interactive debugger, and debugger PIN protections may apply. Remote code execution is therefore not demonstrated.

Confidence: High for the configuration fact; conditional for exploitation.

### SEC-10 — No application-level login throttling

Location: `login()`, lines 82–96.&#x20;

baseline_secure_coding_api(1).py



Demonstrated facts: The login handler compares submitted credentials and immediately returns 401 on failure. No attempt counter, cooldown, or account-lockout logic is visible.

Attacker-controlled flow: Repeated `POST /login` requests → credential comparisons → repeated authentication outcomes.

Root cause: No visible application-level controls against repeated authentication attempts.

Preconditions and impact: If no external rate limiter is present, attackers could conduct online password guessing or credential-stuffing attempts.

Proposed test: In an isolated environment, submit a bounded series of incorrect login attempts. Check for throttling, temporary rejection, or lockout.

Assumptions and uncertainty: External gateways or middleware may supply controls not shown in the provided source. No password-guessing resistance policy is specified.

Confidence: Medium for the end-to-end vulnerability; high that no such control is implemented in the visible handler.

## 3. Cross-cutting observations

Three security concerns are particularly important.

First, authentication state is established but not enforced. The application creates sessions containing identity, role, student ID, and course assignments, yet none of the profile, grade, or file endpoints consult those values. This is directly demonstrated by the source. The proper authorization matrix remains an inferred requirement.

Second, vulnerabilities could interact. The unrestricted file endpoint may permit retrieval of the application source. That source contains both predefined account credentials and the session signing secret. This is a plausible attack chain, not a verified exploit.

Third, authorization and data validation are separate problems. Adding role checks alone would not establish correct grade values, valid student identifiers, or legitimate student/course relationships. Both access controls and integrity constraints would need independent verification.

## 4. Review limitations and conclusion

This review establishes the presence or absence of checks in the supplied handlers; it does not establish actual network reachability, file permissions, deployment configuration, external middleware, or complete institutional authorization policies.

The strongest findings are SEC-01 (grade modification), SEC-02/03 (student data access), and SEC-04 (file traversal) because their vulnerable data flows and missing checks are directly visible. SEC-05 through SEC-10 describe additional weaknesses or deployment-dependent risks.

The recommended next verification step is to test authorization boundaries and file containment using isolated test data, then validate the assumed academic access policies before assigning final remediation requirements.

No patches have been generated. The absence of additional findings must not be interpreted as proof that the application is secure.