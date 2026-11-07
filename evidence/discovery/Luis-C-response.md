# Part III — Static Security Review (C)

The review below uses exclusively the supplied Python source code and the explicit security requirements R1–R7. It does not assume that the application is production-ready or that requirements not specified in the exercise are mandatory.

## 1. Findings summary

I identified 8 distinct security findings, covering authentication, authorization, input validation, file access and error handling.

| ID  | Finding                                                      | Affected function(s)                                         | Severity    | Confidence |
| --- | ------------------------------------------------------------ | ------------------------------------------------------------ | ----------- | ---------- |
| F01 | Missing authentication on protected endpoints                | `get_profile`, `get_grades`, `update_grade`, `download_file` | High        | High       |
| F02 | Missing object-level and role-based authorization            | `get_profile`, `get_grades`, `update_grade`                  | High        | High       |
| F03 | Arbitrary grade modification and insufficient validation     | `update_grade`                                               | High        | High       |
| F04 | Path traversal in material downloads                         | `download_file`                                              | High        | High       |
| F05 | Hardcoded session signing secret                             | Application configuration                                    | High        | High       |
| F06 | Plaintext credentials stored in source code                  | `USERS`, `login`                                             | High        | High       |
| F07 | Insufficient input validation for student identifiers        | `get_profile`, `get_grades`                                  | Medium      | High       |
| F08 | Information disclosure through error handling and debug mode | `handle_error`, application startup                          | Medium–High | High       |

Severity is an assessment of potential impact under the supplied application context, not a result from an automated scanner.

## 2. Supporting explanations

### F01 — Missing authentication on protected endpoints

- Location: `get_profile()`, `get_grades()`, `update_grade()`, `download_file()`.
- Attacker-controlled input: HTTP requests to protected endpoints without an authenticated session.
- Root cause: The functions do not check whether `flask.session` contains an authenticated user before processing requests.
- Requirement violated: R1.

Impact: Unauthenticated users can retrieve student profiles, obtain grade records, modify grades and download teaching materials.

Proposed test:

1. Start a new client session without logging in.
2. Request each protected endpoint.
3. Verify that every request returns HTTP 401.
4. Confirm that no information is disclosed and no data is modified.

Confidence: High. The absence of authentication checks is directly observable.

### F02 — Missing object-level and role-based authorization

- Location: `get_profile()`, `get_grades()`, `update_grade()`.
- Attacker-controlled input: `student_id`, `course_id` and the authenticated user's session.
- Root cause: The endpoints retrieve or modify records based on supplied identifiers without checking ownership, role or professor course assignments.
- Requirements violated: R2, R3 and R4.

Specific problems:

- Students can request another student's profile.
- Students can retrieve another student's grades.
- Professors can access student profiles, despite the explicit prohibition.
- Professors can retrieve grades for courses outside their assignments.
- Professors can modify grades for courses outside their assignments.
- Administrators have no explicit authorization checks either, although the intended policy permits their access.

Impact: Unauthorized access to confidential academic information and unauthorized modification of academic records.

Proposed test:

Authenticate as Alice (`student_id=1001`) and attempt to:

- Retrieve Bob's profile (`1002`).
- Retrieve Bob's grades.
- Modify Bob's grades.

Then authenticate as `prof_srs` and attempt to:

- Retrieve a student profile.
- Retrieve grades for SSD.
- Modify grades for SSD.

Expected results are HTTP 403 for authenticated but unauthorized requests.

Confidence: High. The missing authorization logic is directly observable.

### F03 — Arbitrary grade modification and insufficient validation

- Location: `update_grade()`.
- Attacker-controlled input: JSON request body containing `student_id`, `course_id` and `grade`.
- Root cause: The endpoint directly consumes JSON fields and modifies `GRADES` without validating their existence, types, ranges or relationships.

Missing controls include:

- JSON object validation.
- Required-field validation.
- Positive and existing student identifier validation.
- Known course validation (SRS and SSD).
- Numeric grade validation between 0 and 20.
- Boolean rejection (`bool` is a subclass of `int` in Python).
- Authorization before modification.

Requirements violated: R3, R4 and R5.

Impact: Attackers can create arbitrary grade records, modify existing grades, introduce invalid data and potentially corrupt the academic dataset.

Proposed test:

Submit requests containing:

| Test input                        | Expected result |
| --------------------------------- | --------------- |
| Grade `25`                        | 400             |
| Grade `-1`                        | 400             |
| Grade `true`                      | 400             |
| Unknown course                    | 400             |
| Nonexistent student               | 400             |
| Missing `grade` field             | 400             |
| Missing JSON body                 | 400             |
| Valid grade without authorization | 401/403         |

After each rejected request, verify that `GRADES` remains unchanged.

Confidence: High.

### F04 — Path traversal in material downloads

- Location: `download_file()`.
- Attacker-controlled input: `path` query parameter.
- Execution path:

```
raw_path = flask.request.args.get("path", "")target = MATERIALS_DIR / raw_pathreturn flask.send_file(target)
```

\- Root cause: The application concatenates an untrusted path with `MATERIALS_DIR` without verifying that the resulting path remains inside the permitted directory.

Python's `pathlib` also allows an absolute right-hand path to override the left-hand directory.

Requirement violated: R6.

Impact: An attacker may retrieve files outside the teaching materials directory, potentially exposing configuration files, application source code or other accessible local files.

Proposed test:

After authentication, attempt requests using:

- `../` directory traversal.
- Nested traversal paths.
- Absolute filesystem paths.

Verify that only files within the canonical materials directory can be returned.

Confidence: High. The absence of path containment validation is directly observable. Actual file disclosure depends on filesystem permissions and available files.

### F05 — Hardcoded session signing secret

\- Location: Application configuration.

```
app.config["SECRET_KEY"] = "dev-secret-key"
```

- Attacker-controlled input: An attacker able to obtain the application source or discover the signing secret.
- Root cause: A predictable, hardcoded secret is used to sign Flask session cookies.

Potential impact: An attacker who knows the secret can potentially forge session cookies containing arbitrary session values, including user identity and role information.

This is particularly relevant because authorization decisions should rely on trustworthy server-side identity and permission information.

Proposed test:

1. Authenticate normally and inspect the session cookie.
2. Using the known secret in a controlled test environment, attempt to construct a modified session cookie.
3. Test whether the application accepts forged identity and role values.

Assumptions: The attacker must know the secret. Its inclusion in source code makes this realistic if the source is accessible.

Confidence: High.

### F06 — Plaintext credentials stored in source code

\- Location: `USERS` dictionary and `login()`.

```
"alice": User(username="alice", password="alicepw", role="student")
```

- Attacker-controlled input: Login username and password.
- Root cause: Passwords are stored directly as plaintext strings rather than password hashes.

Potential impact: Anyone obtaining the application source or memory containing the user records can retrieve all account passwords. Credential reuse could extend the impact beyond this application.

Proposed test:

Inspect the user records and verify whether stored password values are directly usable as login credentials.

Assumptions: The exercise does not explicitly define password-storage requirements. Nevertheless, plaintext password storage is an established security weakness, independently of the access-control violations.

Confidence: High.

### F07 — Insufficient student identifier validation

\- Location: `get_profile()`, `get_grades()`.

```
profile = STUDENT_PROFILES.get(int(student_id))
```

```
sid = int(student_id)
```

- Attacker-controlled input: URL path parameter `student_id`.
- Root cause: The application converts the input to an integer but does not verify that it is positive.

Additionally, invalid strings cause `ValueError`, which is subsequently handled by the generic exception handler.

Requirement violated: R5.

Potential impact: Invalid identifiers are not rejected through appropriate client errors. Negative and zero identifiers are accepted as valid integer inputs, even though they are outside the specified input policy.

Proposed test:

Try the following identifiers:

- `0`
- `-1`
- `abc`
- `1001`

Verify that non-positive and malformed identifiers return HTTP 400 and that valid positive identifiers follow the appropriate authorization checks.

Confidence: High.

### F08 — Information disclosure through error handling and debug mode

\- Location: `handle_error()`, application startup.

```
@app.errorhandler(Exception)def handle_error(exc):    return {        "error": str(exc),        "type": exc.__class__.__name__,    }, 500
```

```
app.run(debug=True, host="0.0.0.0", port=5001)
```

- Attacker-controlled input: Requests that trigger application exceptions, including malformed JSON, missing fields and invalid identifiers.
- Root cause: The exception handler returns internal exception messages and class names directly to clients. Furthermore, debug mode is explicitly enabled.

Requirement violated: R7.

Potential impact:

- Disclosure of internal implementation details.
- Exposure of filesystem paths and exception information.
- Additional debugging information through Flask's development debugger if accessible.

Debug mode is particularly concerning if the application is exposed to untrusted networks. However, remote code execution should not be claimed solely from this configuration without establishing the actual debugger accessibility and protection conditions.

Proposed test:

Trigger exceptions through malformed requests and verify whether responses contain internal paths, implementation details or exception messages.

Separately, inspect whether the development debugger is accessible remotely.

Confidence: High for error information disclosure; conditional for debugger exposure.

# 3. Consolidated findings table — Part III

The following table provides the consolidated structure requested for comparison between A, B, C, Bandit and Semgrep.

Important: The A and B model responses and the actual Bandit and Semgrep reports were not included in this request. Their results cannot be reliably populated. I have marked these fields as pending rather than inventing scanner detections.

| ID  | Root cause and affected operation                      | Bandit rule | Semgrep rule | A       | B       | C          | Validation status       |
| --- | ------------------------------------------------------ | ----------- | ------------ | ------- | ------- | ---------- | ----------------------- |
| F01 | Missing authentication — protected endpoints           | Pending     | Pending      | Pending | Pending | Identified | Confirmed               |
| F02 | Missing authorization — profiles and grades            | Pending     | Pending      | Pending | Pending | Identified | Confirmed               |
| F03 | Insufficient grade validation and unrestricted updates | Pending     | Pending      | Pending | Pending | Identified | Confirmed               |
| F04 | Path traversal — file downloads                        | Pending     | Pending      | Pending | Pending | Identified | Confirmed               |
| F05 | Hardcoded Flask session secret                         | Pending     | Pending      | Pending | Pending | Identified | Confirmed               |
| F06 | Plaintext password storage                             | Pending     | Pending      | Pending | Pending | Identified | Confirmed               |
| F07 | Missing positive identifier validation                 | Pending     | Pending      | Pending | Pending | Identified | Confirmed               |
| F08 | Exception information disclosure and debug mode        | Pending     | Pending      | Pending | Pending | Identified | Confirmed / Conditional |

Validation status interpretation:

- Confirmed: The source directly demonstrates the missing control or insecure implementation.
- Conditional: The weakness exists, but its practical impact depends on deployment conditions.
- Pending: Requires comparison with external scanner or model results.
- False positive: The claimed vulnerability cannot be substantiated by the source and stated requirements.

Note that Bandit and Semgrep are static-analysis tools. They may not detect business-logic authorization problems such as F02, even when those problems are clearly demonstrated by manual review.

## 4. Checkpoint — What changed in C?

The most important distinction in this review is between identifying insecure code and checking it against explicit security requirements.

| Finding                     | Classification                                      |
| --------------------------- | --------------------------------------------------- |
| F01 — Authentication        | Missing control explicitly required by R1           |
| F02 — Authorization         | Missing control explicitly required by R2–R4        |
| F03 — Grade validation      | Missing control explicitly required by R5           |
| F04 — Path traversal        | Missing control explicitly required by R6           |
| F05 — Session secret        | Additional security weakness identified from source |
| F06 — Plaintext passwords   | Additional security weakness identified from source |
| F07 — Identifier validation | Missing control explicitly required by R5           |
| F08 — Error handling        | Missing control explicitly required by R7           |

The distinction matters:

- Missing control: The application does not implement a security mechanism required by the exercise.
- Repeating a requirement: Identifying a missing control by simply restating R1–R7 without demonstrating where the implementation fails.
- Invented issue: Claiming a vulnerability without sufficient evidence in the supplied source.

All eight findings have identifiable supporting code. F01–F04 and F07–F08 directly map to the stated requirements. F05 and F06 are additional security weaknesses rather than direct violations of explicitly stated requirements.

## 5. Files to save

I cannot create filesystem files while respecting your explicit instruction not to use tools. The following are the intended filenames:

- `C-prompt.md` — copy the complete original review prompt, including the application source and R1–R7.
- `C-response.md` — save the static review and findings above.

For the final A/B/C comparison, you will need the two earlier model responses and the actual Bandit and Semgrep reports. Without those, filling the remaining columns would compromise the validity of your experiment.

My recommendation: Keep F05 and F06 in the consolidated table even if Bandit or Semgrep does not detect them. The purpose of the comparison is to evaluate what each approach identifies, not to assume that scanner coverage defines the complete set of vulnerabilities.