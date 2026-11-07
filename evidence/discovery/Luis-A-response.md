# Static Security Review — Flask Application

Scope: Source-code-only static analysis of the supplied Flask application.

Methodology: Manual review of authentication, authorization, session management, input validation, data access, file handling, error handling, and application configuration.

Limitations: No code execution, dynamic testing, external references, or assumptions about undocumented business requirements.

## 1. Findings summary

I identified 9 potential security findings, including several directly demonstrated weaknesses and others dependent on the application's intended access-control policy.

| ID   | Finding                                         | Affected function          | Severity\* | Confidence |
| ---- | ----------------------------------------------- | -------------------------- | ---------- | ---------- |
| F-01 | Missing authorization on student profiles       | `get_profile()`            | High       | High       |
| F-02 | Missing authorization on grade retrieval        | `get_grades()`             | High       | High       |
| F-03 | Unrestricted grade modification                 | `update_grade()`           | Critical   | High       |
| F-04 | Directory traversal in file download            | `download_file()`          | High       | High       |
| F-05 | Hardcoded secret key                            | Application configuration  | High       | High       |
| F-06 | Insecure password storage                       | `User`, `USERS`, `login()` | High       | High       |
| F-07 | Session fixation / incomplete session lifecycle | `login()`                  | Medium     | Medium     |
| F-08 | Sensitive exception disclosure                  | `handle_error()`           | Medium     | High       |
| F-09 | Debug mode enabled                              | `app.run()`                | High       | High       |

Severity is provisional and assumes the application is deployed in an environment where the affected endpoints are accessible to potentially untrusted users. It is not a formal risk rating.

## 2. Supporting explanations

### F-01 — Missing authorization on student profiles



High

High confidence



Location: `get_profile()` — `GET /students/<student_id>/profile`

Affected code:

```
@app.get("/students/<student_id>/profile")def get_profile(student_id):    profile = STUDENT_PROFILES.get(int(student_id))    if profile is None:        return {"error": "student not found"}, 404    return flask.jsonify(profile)
```

Attacker-controlled input and data flow

The attacker controls `student_id` through the URL path.

The value is converted to an integer and used directly to retrieve a student profile from `STUDENT_PROFILES`.

There is no authentication or authorization check before returning the profile.

Missing security control / root cause

The endpoint does not verify:

- Whether the requester is authenticated.
- Whether the requester is authorized to access the requested student's information.

This is consistent with an Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA) vulnerability.

Preconditions and impact

An attacker only needs network access to the endpoint.

Potential consequences include unauthorized disclosure of:

- Student names.
- Email addresses.
- Academic programme information.
- Student identifiers.

Proposed test

1. Send a GET request to `/students/1001/profile` without authenticating.
2. Repeat using another student's identifier.
3. Authenticate as Alice and request Bob's profile.

Check whether the application returns profiles in all three cases.

Assumptions and uncertainty

Assumption: Student profiles should only be accessible to authorized users.

If these profiles are intentionally public, the finding's security significance changes.

### F-02 — Missing authorization on grade retrieval



High

High confidence



Location: `get_grades()` — `GET /grades/<student_id>`

Affected code:

```
@app.get("/grades/<student_id>")def get_grades(student_id):    sid = int(student_id)    rows = [row for row in GRADES if row["student_id"] == sid]    return flask.jsonify(rows)
```

Attacker-controlled input and data flow

The attacker controls the `student_id` URL parameter.

The application converts it to an integer and retrieves every grade associated with that identifier.

The returned records are serialized directly into JSON.

Missing security control / root cause

There is no authentication or authorization enforcement.

In particular, the application does not establish whether:

- A student is requesting their own grades.
- A professor teaches the requested course.
- An administrator has permission to access the records.

This creates a potential IDOR/BOLA vulnerability.

Preconditions and impact

An attacker must be able to reach the endpoint.

Potential impact includes unauthorized disclosure of students' academic results, including grades from multiple courses.

Proposed test

1. Request `/grades/1001` without authentication.
2. Authenticate as Bob and request `/grades/1001`.
3. Authenticate as a professor and request grades belonging to students outside their assigned courses.

Compare the returned records.

Assumptions and uncertainty

Assumption: Academic grades are confidential and access is restricted according to user roles.

The precise authorization matrix is not provided.

### F-03 — Unrestricted grade modification



Critical

High confidence



Location: `update_grade()` — `POST /grades/update`

Affected code:

```
@app.post("/grades/update")def update_grade():    data = flask.request.get_json()    student_id = data["student_id"]    course_id = data["course_id"]    grade = data["grade"]    row = find_grade(student_id, course_id)    if row is None:        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})    else:        row["grade"] = grade
```

Attacker-controlled input and data flow

The attacker controls all three JSON parameters:

- `student_id`
- `course_id`
- `grade`

These values are used directly to locate, create, or modify records in `GRADES`.

The endpoint does not check the user's session, role, or course permissions.

Missing security control / root cause

The application lacks server-side authorization for a sensitive operation.

Although the application defines student, professor, and administrator roles, those roles are never checked in this endpoint.

The application also lacks input validation for the grade value.

For example, it does not establish:

- Whether the grade is numeric.
- Whether the grade falls within the permitted grading range.
- Whether the student and course exist.
- Whether the requester can modify that particular student's grade.

Preconditions and impact

An attacker needs network access to the endpoint.

No authenticated session appears necessary.

Potential consequences:

- Unauthorized modification of existing grades.
- Creation of arbitrary grade records.
- Manipulation of academic results.
- Integrity violations affecting academic records.

Proposed test

Submit a POST request without authentication:

```
{
    "student_id": 1001,
    "course_id": "SRS",
    "grade": 20
}
```

Then retrieve `/grades/1001` and check whether the modification persisted.

Additional tests should attempt:

- Negative grades.
- Grades above the permitted maximum.
- Non-numeric values.
- Non-existent student and course identifiers.

Assumptions and uncertainty

The missing authorization is directly demonstrated.

The exact grading constraints are unknown. A 0–20 grading range is a reasonable assumption in this example, but the application does not explicitly define it.

The Critical severity assumes that unauthenticated grade manipulation is possible in a deployed academic system.

### F-04 — Directory traversal in file download



High

High confidence



Location: `download_file()` — `GET /files`

Affected code:

```
@app.get("/files")def download_file():    raw_path = flask.request.args.get("path", "")    target = MATERIALS_DIR / raw_path    return flask.send_file(target)
```

Attacker-controlled input and data flow

The attacker controls the `path` query parameter.

The application joins the supplied value with `MATERIALS_DIR` and passes the resulting path directly to `flask.send_file()`.

There is no validation or restriction preventing path traversal.

For example:

```
GET /files?path=../../some-sensitive-file
```

The relative path components can cause the resulting path to reference locations outside `MATERIALS_DIR`.

Missing security control / root cause

The application does not enforce directory confinement.

It assumes that joining a user-controlled path with the materials directory guarantees that the resulting file remains inside that directory.

That assumption is incorrect.

There is also no authentication or authorization check for file downloads.

Preconditions and impact

The attacker needs network access to the endpoint and sufficient operating-system permissions for the application process to read the target file.

Potential consequences include:

- Unauthorized access to files outside the intended directory.
- Disclosure of application configuration.
- Exposure of sensitive local files accessible to the Flask process.

The actual impact depends on the deployment environment and filesystem permissions.

Proposed test

1\. Request an existing file:

```
GET /files?path=srs-summary.txt
```

2\. Attempt traversal:

```
GET /files?path=../../some-sensitive-file
```

3\. Check whether a file outside `MATERIALS_DIR` can be retrieved.

Use a harmless test file created specifically for this purpose.

Assumptions and uncertainty

The traversal risk is directly demonstrated by the absence of path confinement.

Whether a particular sensitive file can be accessed depends on the filesystem and operating-system permissions.

### F-05 — Hardcoded secret key



High

High confidence



Location: Application configuration

Affected code:

```
app = flask.Flask(__name__)app.config["SECRET_KEY"] = "dev-secret-key"
```

Attacker-controlled input and data flow

There is no direct attacker-controlled input involved.

The vulnerability originates from the application's configuration.

Flask uses the secret key to cryptographically sign session cookies.

Missing security control / root cause

A static, predictable development secret is embedded directly in the source code.

If this key is used in a deployed environment, anyone who obtains it can potentially forge valid Flask session cookies.

Since the application stores authorization-related information in the session, this can have additional consequences.

Preconditions and impact

The attacker must know or obtain the secret key.

In this example, the key is explicitly available in the source.

Potential consequences include:

- Session cookie forgery.
- Impersonation of other users.
- Manipulation of session attributes such as `role`, `student_id`, and `courses`.

For example, an attacker could attempt to construct a session representing an administrator.

Proposed test

1. Authenticate as a normal student.
2. Inspect the session cookie.
3. Using the known development key, attempt to construct a valid signed session containing:

```
{    "user": "admin1",    "role": "admin",    "student_id": None,    "courses": []}
```

4\. Submit the resulting cookie and inspect the response from `/me`.

Assumptions and uncertainty

The hardcoded key is demonstrated.

The consequences depend on whether this key is used outside a development environment and whether session attributes are trusted by other application components.

### F-06 — Insecure password storage



High

High confidence



Location: `User`, `USERS`, `login()`

Affected code:

```
@dataclasses.dataclassclass User:    username: str    password: str    role: str
```

Example user definition:

```
"alice": User(    username="alice",    password="alicepw",    role="student")
```

Authentication:

```
if user is None or user.password != password:    return {"error": "invalid credentials"}, 401
```

Attacker-controlled input and data flow

The attacker controls the username and password submitted through the login form.

The application compares the supplied password directly against the stored password.

Missing security control / root cause

Passwords are stored in plaintext rather than using a dedicated password hashing algorithm.

The application does not use password-specific hashing mechanisms such as Argon2id, scrypt, or bcrypt.

Preconditions and impact

An attacker would need access to the application source, memory, or another location where the user records are stored.

Potential consequences include:

- Disclosure of all user passwords.
- Account compromise.
- Password reuse attacks against other services.

Proposed test

Inspect the stored user records and verify whether the password values are directly readable.

The supplied source already demonstrates that they are.

Assumptions and uncertainty

The insecure storage is directly demonstrated.

The actual exposure depends on how user records are managed in a production deployment. The in-memory implementation does not establish whether a separate production authentication system exists.

### F-07 — Potential session fixation / incomplete session lifecycle



Medium

Medium confidence



Location: `login()` — `POST /login`

Affected code:

```
flask.session["user"] = user.usernameflask.session["role"] = user.roleflask.session["student_id"] = user.student_idflask.session["courses"] = user.courses or []
```

Attacker-controlled input and data flow

The attacker controls the login credentials.

Upon successful authentication, the application writes identity and authorization attributes into the existing Flask session.

Missing security control / root cause

The application does not explicitly regenerate or otherwise rotate the session identifier after authentication.

It also does not explicitly configure session cookie security attributes.

Potentially relevant missing settings include:

- `SESSION_COOKIE_SECURE`
- `SESSION_COOKIE_HTTPONLY`
- `SESSION_COOKIE_SAMESITE`

Preconditions and impact

Session fixation depends on whether an attacker can establish or control a victim's pre-authentication session identifier and subsequently reuse it.

Potential consequences include session hijacking or unauthorized access to an authenticated session.

Proposed test

1. Obtain a session cookie before authentication.
2. Authenticate using that session.
3. Check whether the session identifier changes.
4. Determine whether the original identifier remains usable for authenticated access.

Also inspect the cookie attributes returned by the application.

Assumptions and uncertainty

This finding requires qualification.

Flask's default session mechanism uses signed client-side cookies rather than a conventional server-side session identifier.

Consequently, the absence of an explicit session ID regeneration call does not, by itself, demonstrate an exploitable session fixation vulnerability.

The missing explicit cookie configuration is demonstrable, but the actual cookie attributes and deployment behavior should be verified.

### F-08 — Sensitive exception disclosure



Medium

High confidence



Location: `handle_error()` — Global exception handler

Affected code:

```
@app.errorhandler(Exception)def handle_error(exc):    return {        "error": str(exc),        "type": exc.__class__.__name__,    }, 500
```

Attacker-controlled input and data flow

Attacker-controlled requests can trigger exceptions through different endpoints.

Examples include:

- Invalid student identifiers.
- Missing JSON fields.
- Invalid JSON request bodies.
- Invalid file paths.

The resulting exception message and class name are returned directly to the requester.

Missing security control / root cause

The application exposes internal exception details instead of returning generic error responses.

This can reveal implementation information that should normally remain internal.

Preconditions and impact

An attacker needs access to an endpoint that can trigger an exception.

Potential consequences include:

- Disclosure of internal implementation details.
- Identification of application behavior.
- Exposure of filesystem paths or other sensitive information contained in exception messages.
- Assistance in developing further attacks.

Proposed test

Submit:

```
GET /students/invalid/profile
```

And:

```
POST /grades/update
Content-Type: application/json

{}
```

Inspect the returned error messages and determine whether they expose internal information.

Assumptions and uncertainty

The disclosure of exception messages and types is directly demonstrated.

Whether a particular exception contains sensitive information depends on the exception and runtime environment.

### F-09 — Debug mode enabled



High

High confidence



Location: Application entry point

Affected code:

```
if __name__ == "__main__":    app.run(debug=True, host="0.0.0.0", port=5001)
```

Attacker-controlled input and execution path

An attacker can potentially send malformed requests to trigger exceptions.

The application runs with Flask debug mode enabled and listens on all network interfaces.

Missing security control / root cause

Debug mode is enabled directly in the application startup configuration.

Flask's interactive debugger can expose sensitive application information and, under certain conditions, provide an interactive code execution interface.

Binding to `0.0.0.0` also makes the development server reachable through network interfaces, subject to firewall and network configuration.

Preconditions and impact

The impact depends on whether this startup configuration is used in a reachable deployment.

Potential consequences include:

- Disclosure of stack traces and internal application state.
- Exposure of the interactive debugger.
- Potential remote code execution if the debugger's security protections are bypassed or otherwise compromised.

Proposed test

1. Start the application using the supplied configuration.
2. Trigger an unhandled exception.
3. Verify whether the interactive debugger is exposed.
4. Check whether the application is reachable from another machine on the network.

Assumptions and uncertainty

Debug mode and network binding are directly demonstrated.

The actual exploitability of the debugger depends on its PIN protection, exposure, runtime configuration, and deployment environment.

The development server configuration may be intentional for local development. If so, this finding should be treated as a deployment configuration risk rather than proof of a production vulnerability.

## 3. Additional observations

The following issues deserve attention but are not included as independent confirmed vulnerabilities in the findings table.

| Observation                      | Relevant location               | Security relevance                                                                                                            |
| -------------------------------- | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Missing login rate limiting      | `login()`                       | Enables password guessing and brute-force attempts.                                                                           |
| No CSRF protection               | POST endpoints                  | Cookie-authenticated requests may be vulnerable to cross-site request forgery, depending on browser and cookie configuration. |
| Missing input validation         | `update_grade()`                | Unexpected data types and values can cause errors or corrupt application state.                                               |
| Unhandled conversion errors      | `get_profile()`, `get_grades()` | Invalid identifiers generate exceptions and HTTP 500 responses.                                                               |
| Missing file access restrictions | `download_file()`               | Any accessible file under the permitted directory can potentially be downloaded without authentication.                       |
| In-memory storage                | `USERS`, `GRADES`               | Data persistence, integrity, and concurrency are not addressed by the implementation.                                         |

These observations should be investigated according to the application's intended requirements and deployment architecture.

## 4. Overall assessment

The most significant issues are the authorization failures and unrestricted grade modification.

The application defines different user roles and course assignments, suggesting that it intends to implement role-based access control. However, the relevant endpoints do not enforce those permissions.

The following attack scenarios are particularly important:

1. Unauthorized academic data disclosure: An unauthenticated attacker can retrieve student profiles and grades by manipulating URL parameters.
2. Academic record manipulation: An unauthenticated attacker can modify existing grades or create new records.
3. Local file disclosure: An attacker can potentially escape the intended materials directory through path traversal.
4. Session impersonation: Knowledge of the hardcoded Flask secret key can enable session forgery.

### Recommended remediation priority

| Priority      | Findings   | Recommended action                                                                                     |
| ------------- | ---------- | ------------------------------------------------------------------------------------------------------ |
| 1 — Immediate | F-03       | Enforce authentication, role-based authorization, and course-level permissions on grade modifications. |
| 2 — Immediate | F-01, F-02 | Implement object-level authorization for student profiles and grades.                                  |
| 3 — High      | F-04       | Enforce canonical path validation and directory confinement.                                           |
| 4 — High      | F-05, F-06 | Replace the hardcoded secret and implement secure password hashing.                                    |
| 5 — High      | F-09       | Disable debug mode outside local development.                                                          |
| 6 — Medium    | F-07, F-08 | Review session lifecycle and cookie settings; prevent exception disclosure.                            |

Final assessment: The supplied application contains multiple directly identifiable security weaknesses, particularly concerning access control and data integrity. The most critical architectural concern is that authentication and authorization are not consistently enforced across the API. Merely defining user roles and storing them in a session does not implement access control.

This review is limited to the supplied source. It does not establish whether additional protections exist in an external reverse proxy, deployment configuration, or infrastructure layer.