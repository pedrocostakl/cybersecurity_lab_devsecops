# Static Security Review — Academic Services REST API

Review type: Static source-code analysis\
Scope: Supplied Flask application and explicitly provided application context\
Approach: Manual review of authentication, authorization, session management, input validation, file handling, information disclosure, and error handling.

The review identifies 10 potential security findings. The most significant concerns are the absence of authorization checks on sensitive endpoints, unrestricted grade modification, and potentially unsafe file access.

The findings distinguish between vulnerabilities directly demonstrated by the source and security implications that depend on the application's intended access-control policy.

## 1. Findings summary

| ID     | Finding                                                         | Affected function                                 | Severity | Confidence |
| ------ | --------------------------------------------------------------- | ------------------------------------------------- | -------- | ---------- |
| SEC-01 | Missing authentication and authorization on sensitive endpoints | Multiple endpoints                                | Critical | High       |
| SEC-02 | Broken object-level authorization (BOLA)                        | `get_profile()`                                   | High     | High       |
| SEC-03 | Unauthorized grade modification                                 | `update_grade()`                                  | Critical | High       |
| SEC-04 | Unauthorized grade retrieval                                    | `get_grades()`                                    | High     | High       |
| SEC-05 | Path traversal in file downloads                                | `download_file()`                                 | High     | High       |
| SEC-06 | Hardcoded application secret key                                | Application configuration                         | High     | High       |
| SEC-07 | Plaintext password storage and comparison                       | `User`, `login()`                                 | High     | High       |
| SEC-08 | Missing session cookie security configuration                   | Application configuration                         | Medium   | High       |
| SEC-09 | Insufficient input validation                                   | `update_grade()`, `get_grades()`, `get_profile()` | Medium   | High       |
| SEC-10 | Excessive error information disclosure                          | `handle_error()`                                  | Medium   | High       |

Severity ratings are preliminary and assume that the API is expected to enforce the role-based access model described in the application context. They are not based on a formal risk assessment.

# 2. Supporting explanations

## SEC-01 — Missing authentication and authorization on sensitive endpoints



Critical

High confidence



Affected locations:

- `get_profile()` — approximately lines 88–92
- `get_grades()` — approximately lines 94–97
- `update_grade()` — approximately lines 99–113
- `download_file()` — approximately lines 115–118

Attacker-controlled input and execution path

An unauthenticated attacker can directly issue HTTP requests to the endpoints above.

For example:

```
GET /grades/1001
```

or:

```
POST /grades/update
Content-Type: application/json

{
    "student_id": 1001,
    "course_id": "SRS",
    "grade": 20
}
```

None of these endpoint implementations checks whether the requester has an authenticated session.

Missing security control and root cause

The application does not implement centralized or endpoint-specific authentication and authorization enforcement.

Although `/login` establishes session information, the other endpoints do not verify the existence of a valid session or inspect the associated role.

The presence of session data therefore does not translate into enforced access control.

Preconditions and potential impact

- Network access to the API.
- No authentication is required by the current endpoint implementations.

Potential consequences include:

- Unauthorized access to student information.
- Exposure of academic records.
- Unauthorized modification of grades.
- Access to teaching materials without authentication.

Proposed test

Send requests to each sensitive endpoint without first authenticating.

Expected secure behavior, assuming authentication is mandatory, would be an HTTP `401 Unauthorized` response.

Assumptions and uncertainty

The application context establishes multiple user roles but does not explicitly define whether all endpoints require authentication. The finding is nevertheless significant because academic records and modification operations would normally require access controls.

The absence of authentication checks is directly demonstrated by the source.

## SEC-02 — Broken object-level authorization (BOLA)



High

High confidence



Affected location: `get_profile()` — approximately lines 88–92.

Attacker-controlled input and execution path

The attacker controls the `student_id` URL parameter:

```
profile = STUDENT_PROFILES.get(int(student_id))
```

The supplied identifier directly determines which student profile is returned.

For example:

```
GET /students/1002/profile
```

A student authenticated as Alice could potentially retrieve Bob's profile by changing the identifier.

Missing security control and root cause

The endpoint does not verify whether the authenticated user is authorized to access the requested student identifier.

There is no ownership check connecting:

```
flask.session["student_id"]
```

with the requested `student_id`.

Preconditions and potential impact

- An attacker must be able to reach the endpoint.
- If access is intended to be restricted to the student's own profile, changing the identifier is sufficient to bypass that restriction.

Potential impact:

- Exposure of personal information, including names, email addresses, and academic programme.
- Enumeration of student records through sequential identifiers.

Proposed test

1. Authenticate as Alice.
2. Request `/students/1001/profile`.
3. Request `/students/1002/profile`.
4. Compare the responses.

If Alice can retrieve Bob's profile despite a self-access-only policy, the vulnerability is confirmed.

Assumptions and uncertainty

The application context does not explicitly state whether students can access other students' profiles. The finding assumes students should only access their own profiles, while professors and administrators may have broader permissions.

The absence of an authorization check is demonstrated; the policy violation depends on the intended access model.

## SEC-03 — Unauthorized grade modification



Critical

High confidence



Affected location: `update_grade()` — approximately lines 99–113.

Attacker-controlled input and execution path

The endpoint accepts three values directly from the request body:

```
student_id = data["student_id"]course_id = data["course_id"]grade = data["grade"]
```

These values are subsequently used to locate and modify grade records:

```
row = find_grade(student_id, course_id)if row is None:    GRADES.append({        "student_id": student_id,        "course_id": course_id,        "grade": grade    })else:    row["grade"] = grade
```

An attacker can submit arbitrary student identifiers, course identifiers, and grades.

For example:

```
POST /grades/update
Content-Type: application/json

{
    "student_id": 1001,
    "course_id": "SRS",
    "grade": 20
}
```

Missing security control and root cause

The application does not verify:

- Whether the requester is authenticated.
- Whether the requester has the professor or administrator role.
- Whether a professor is authorized to modify grades for the specified course.
- Whether the student and course combination is valid.
- Whether the submitted grade falls within an acceptable range.

The root cause is the absence of authorization and business-rule enforcement before modifying academic records.

Preconditions and potential impact

An attacker needs access to the endpoint, but no authentication is currently enforced.

Potential consequences:

- Grade manipulation.
- Creation of arbitrary grade records.
- Unauthorized academic record modification.
- Compromise of academic record integrity.

Proposed test

Submit grade updates using:

1. No authenticated session.
2. A student account.
3. A professor account assigned to `SRS`, attempting to modify `SSD`.
4. An administrator account.

Check whether the API enforces the expected role and course restrictions.

Assumptions and uncertainty

The application context establishes professor course assignments and administrator roles. This suggests that grade modification should be restricted according to these roles.

The precise permission model is unspecified. For example, whether administrators can modify all grades or whether professors can modify grades only within assigned courses requires confirmation.

The unrestricted modification capability is directly demonstrated.

## SEC-04 — Unauthorized grade retrieval



High

High confidence



Affected location: `get_grades()` — approximately lines 94–97.

Attacker-controlled input and execution path

The attacker controls the `student_id` parameter:

```
sid = int(student_id)rows = [row for row in GRADES if row["student_id"] == sid]
```

The endpoint returns every grade associated with the supplied student identifier.

Example:

```
GET /grades/1001
```

Missing security control and root cause

There is no authorization check connecting the requested student identifier with the authenticated user's identity or role.

The endpoint does not distinguish between:

- Students requesting their own grades.
- Professors requesting grades for assigned courses.
- Administrators accessing academic records.
- Unauthenticated users.

Preconditions and potential impact

An attacker needs network access to the endpoint.

Potential consequences include unauthorized disclosure of academic performance and enumeration of student records.

Proposed test

Authenticate as Alice and request:

```
GET /grades/1002
```

Verify whether Alice receives Bob's grades.

Also test whether a professor assigned to `SRS` can retrieve grades for `SSD`.

Assumptions and uncertainty

The expected restrictions depend on the academic access-control policy. The application context does not explicitly define student or professor grade visibility.

The unrestricted retrieval behavior is directly demonstrated.

## SEC-05 — Path traversal in file downloads



High

High confidence



Affected location: `download_file()` — approximately lines 115–118.

Attacker-controlled input and execution path

The attacker controls the `path` query parameter:

```
raw_path = flask.request.args.get("path", "")target = MATERIALS_DIR / raw_pathreturn flask.send_file(target)
```

The supplied path is combined with the materials directory without validation or containment checks.

For example:

```
GET /files?path=../../some-file.txt
```

Depending on the filesystem and target file, path traversal may allow access to files outside the intended materials directory.

Missing security control and root cause

The application does not:

- Reject path traversal sequences.
- Restrict downloads to explicitly authorized files.
- Verify that the resolved target remains inside `MATERIALS_DIR`.
- Enforce file-level authorization.

The root cause is trusting a user-controlled filesystem path.

Preconditions and potential impact

- The application process must have filesystem read permissions for the targeted file.
- The file must exist and be accessible.
- The attacker must be able to reach the endpoint.

Potential consequences include disclosure of application configuration, source files, and other readable files.

Proposed test

Attempt to retrieve a known file outside the materials directory using relative traversal sequences.

For example, create a harmless test file in the parent directory and attempt to download it.

Confirm whether the endpoint returns its contents.

Assumptions and uncertainty

The exact impact depends on the deployment filesystem, operating-system path semantics, and process permissions.

Path traversal is a demonstrated weakness in the path-handling logic. Successful disclosure of arbitrary files has not been demonstrated through execution.

## SEC-06 — Hardcoded application secret key



High

High confidence



Affected location: Application initialization — approximately line 8.

Relevant code:

```
app.config["SECRET_KEY"] = "dev-secret-key"
```

Attacker-controlled input and execution path

The secret key is not attacker-controlled input. Instead, it is a sensitive application value embedded directly in the source code.

Flask uses this key to sign session cookies.

Anyone with access to the source can obtain the signing key.

Missing security control and root cause

The application uses a predictable development secret rather than a securely generated, deployment-specific secret.

There is no indication of secret management through environment variables or another protected configuration mechanism.

Preconditions and potential impact

An attacker must obtain the source code or otherwise discover the secret.

Potential consequences include:

- Forging Flask session cookies.
- Manipulating session values, including role and identity information.
- Impersonating other users, depending on the application's session implementation and validation behavior.

This is particularly relevant because the application stores authorization-related attributes in the session.

Proposed test

Inspect the deployed configuration and determine whether the application uses the same hardcoded key.

If so, assess whether a forged session cookie containing modified role and identity values is accepted.

Assumptions and uncertainty

The hardcoded key is directly demonstrated.

Session forgery and privilege escalation are potential consequences, not independently demonstrated exploits.

## SEC-07 — Plaintext password storage and comparison



High

High confidence



Affected locations:

- `User` dataclass — approximately lines 24–30.
- `USERS` dictionary — approximately lines 33–42.
- `login()` — approximately lines 66–72.

Attacker-controlled input and execution path

The attacker provides credentials through form parameters:

```
username = flask.request.form.get("username", "")password = flask.request.form.get("password", "")
```

The application compares the submitted password directly against the stored value:

```
user = USERS.get(username)if user is None or user.password != password:    return {"error": "invalid credentials"}, 401
```

Passwords are stored directly as strings in the `USERS` dictionary.

Missing security control and root cause

The application does not implement password hashing with a dedicated password-hashing algorithm.

It also uses demonstration credentials embedded directly in the source code.

Appropriate password storage should use a salted, computationally expensive password-hashing mechanism.

Preconditions and potential impact

An attacker would need access to the source, application memory, or another source of credential disclosure.

Potential consequences:

- Exposure of user passwords.
- Credential reuse attacks against other services.
- Account compromise.

Proposed test

Inspect the stored password representation and authentication comparison.

Confirm whether stored values are plaintext or password hashes and whether a dedicated password verification mechanism is used.

Assumptions and uncertainty

The plaintext storage is directly demonstrated.

The impact of credential reuse depends on whether users reuse these passwords elsewhere.

## SEC-08 — Missing session cookie security configuration



Medium

High confidence



Affected location: Application configuration — approximately lines 6–8.

Attacker-controlled input and execution path

The login endpoint creates a session:

```
flask.session["user"] = user.usernameflask.session["role"] = user.roleflask.session["student_id"] = user.student_id
```

Flask subsequently stores the session in a client-side cookie.

However, the application does not explicitly configure the following security attributes:

- `SESSION_COOKIE_SECURE`
- `SESSION_COOKIE_HTTPONLY`
- `SESSION_COOKIE_SAMESITE`

Missing security control and root cause

The source does not explicitly establish hardened session cookie settings.

These settings help protect session cookies against interception, client-side script access, and certain cross-site request scenarios.

Preconditions and potential impact

The actual impact depends on Flask defaults, deployment configuration, and whether HTTPS is enforced.

Potential consequences include:

- Session cookie exposure over insecure HTTP connections.
- Increased session theft risk in the presence of XSS.
- Increased exposure to cross-site request attacks.

Proposed test

Authenticate and inspect the resulting `Set-Cookie` response header.

Verify whether the cookie includes:

- `Secure`
- `HttpOnly`
- An appropriate `SameSite` policy.

Assumptions and uncertainty

The absence of explicit configuration is demonstrated.

This does not prove that the resulting cookies lack these attributes: framework defaults and deployment-level configuration must also be considered.

## SEC-09 — Insufficient input validation



Medium

High confidence



Affected locations:

- `update_grade()` — approximately lines 99–113.
- `get_grades()` — approximately lines 94–97.
- `get_profile()` — approximately lines 88–92.

Attacker-controlled input and execution path

The application accepts external values without comprehensive validation.

Examples:

```
data = flask.request.get_json()student_id = data["student_id"]course_id = data["course_id"]grade = data["grade"]
```

And:

```
sid = int(student_id)
```

The application does not explicitly validate the types, ranges, or business constraints of these values.

Missing security control and root cause

There is no structured validation layer enforcing:

- Integer student identifiers.
- Valid course identifiers.
- Numeric grades.
- Permitted grade ranges.
- Valid student/course relationships.
- Required JSON fields and expected data types.

Preconditions and potential impact

An attacker must be able to reach the corresponding endpoints.

Potential consequences include:

- Invalid academic records.
- Application exceptions.
- Unexpected data states.
- Denial of service through repeated malformed requests, depending on deployment behavior.

For example, the application could accept an invalid grade such as:

```
{
    "student_id": 1001,
    "course_id": "SRS",
    "grade": "invalid"
}
```

Proposed test

Submit:

- Missing JSON fields.
- Incorrect data types.
- Negative grades.
- Grades above the permitted maximum.
- Unknown course identifiers.
- Invalid student identifiers.

Inspect the responses and resulting application state.

Assumptions and uncertainty

The lack of explicit validation is demonstrated.

The permitted grade range and exact course/student constraints are not defined in the supplied context. A specific business-rule violation cannot be asserted without that policy.

## SEC-10 — Excessive error information disclosure



Medium

High confidence



Affected location: `handle_error()` — approximately lines 120–124.

Relevant code:

```
@app.errorhandler(Exception)def handle_error(exc):    return {        "error": str(exc),        "type": exc.__class__.__name__,    }, 500
```

Attacker-controlled input and execution path

An attacker can potentially trigger application exceptions through malformed input or invalid resource requests.

For example:

- Supplying a non-numeric student identifier.
- Omitting required JSON fields.
- Requesting a nonexistent file.

The global error handler returns the exception message and class name to the requester.

Missing security control and root cause

The application does not distinguish between internal diagnostic information and externally exposed error messages.

The root cause is returning raw exception details directly to clients.

Preconditions and potential impact

An attacker needs access to an endpoint capable of generating an exception.

Potential consequences include disclosure of:

- Internal implementation details.
- Filesystem paths.
- Framework or library behavior.
- Information useful for developing further attacks.

Proposed test

Send malformed requests that trigger exceptions and inspect the HTTP response body.

Determine whether internal filesystem paths, implementation details, or other sensitive information are exposed.

Assumptions and uncertainty

The disclosure mechanism is directly demonstrated.

The sensitivity of individual exception messages depends on the exception generated and the deployment environment.

# 3. Additional observations and limitations

A few aspects deserve attention but are not necessarily independent vulnerabilities.

| Area               | Observation                                                              | Security relevance                                                                                |
| ------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| Logout             | `logout()` clears the current session.                                   | No obvious issue in the provided implementation.                                                  |
| Session contents   | Role, username, student ID, and courses are stored in the session.       | These values must be trusted only after appropriate authentication and authorization enforcement. |
| Debug mode         | `app.run(debug=True)` enables Flask's debugger.                          | Dangerous if exposed in an accessible deployment environment.                                     |
| Network exposure   | `host="0.0.0.0"` binds the development server to all network interfaces. | Increases exposure if network access is not restricted.                                           |
| Rate limiting      | No rate limiting is implemented.                                         | Brute-force login attempts and request abuse may be possible.                                     |
| CSRF               | No CSRF protection is explicitly implemented.                            | Relevant if browser sessions are used for authenticated state-changing requests.                  |
| File authorization | No file-level access policy is implemented.                              | Teaching materials may be accessible without authentication or role restrictions.                 |

These observations require additional context before assigning definitive vulnerability classifications or severity.

# 4. Overall assessment

The application presents several significant security weaknesses, particularly in its access-control model.

The most important architectural issue is that authentication and authorization are not consistently enforced across the API.

Although the application establishes roles and stores user-specific information in the session, these mechanisms are not used to restrict access to sensitive operations.

The three most critical areas are:

1. Access control: Sensitive endpoints do not enforce authentication or role-based authorization.
2. Academic record integrity: Grade modification accepts arbitrary student, course, and grade values without permission checks.
3. File access: User-controlled paths are passed directly to the filesystem without validating their containment within the materials directory.

The remaining findings concern session security, credential management, input validation, and information disclosure.

Important qualification: This is a source-level assessment, not an exploitation assessment. The findings establish weaknesses in the supplied implementation, but their effective impact depends on deployment configuration, surrounding infrastructure, and the intended academic-services authorization policy.

The absence of a finding in a particular area should not be interpreted as evidence that the corresponding security property is satisfied.