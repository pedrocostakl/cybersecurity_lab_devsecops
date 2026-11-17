"""Selected vulnerability 1 - grade authorization (findings F04 and F05).

Requirements: R1 (authentication), R2 (students: own records only),
R3 (professors: assigned courses only; admins: all grades), R4 (check every
request, filter grade lists, deny when nothing is permitted), R7 (401/403,
denied updates leave data unchanged).
"""

import copy

import baseline_secure_coding_api as api


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


# --- Supplied worked example (not part of the assessed tests) ---------------

def test_assigned_professor_can_update_grade(client):
    login(client, "prof_srs", "profpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )

    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18


# --- Legitimate operations that must keep working ---------------------------

def test_admin_can_update_any_course_grade(client):
    login(client, "admin1", "adminpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 12},
    )

    assert response.status_code == 200
    assert api.find_grade(1001, "SSD")["grade"] == 12


def test_student_can_read_own_grades(client):
    login(client, "alice", "alicepw")

    response = client.get("/grades/1001")

    assert response.status_code == 200
    rows = response.get_json()
    assert {(r["course_id"], r["grade"]) for r in rows} == {("SRS", 14), ("SSD", 16)}
    assert all(r["student_id"] == 1001 for r in rows)


def test_admin_can_read_all_grades_of_a_student(client):
    login(client, "admin1", "adminpw")

    response = client.get("/grades/1001")

    assert response.status_code == 200
    assert {r["course_id"] for r in response.get_json()} == {"SRS", "SSD"}


# --- Forbidden operations (update) ------------------------------------------

def test_professor_cannot_update_grade_in_unassigned_course(client):
    before = copy.deepcopy(api.GRADES)
    login(client, "prof_srs", "profpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 0},
    )

    assert response.status_code == 403
    assert api.GRADES == before


def test_student_cannot_update_own_grade(client):
    """Ownership of the record must not grant write permission (R3/R4)."""
    before = copy.deepcopy(api.GRADES)
    login(client, "alice", "alicepw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )

    assert response.status_code == 403
    assert api.GRADES == before


def test_unauthenticated_update_is_rejected_without_change(client):
    before = copy.deepcopy(api.GRADES)

    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 0},
    )

    assert response.status_code == 401
    assert api.GRADES == before


def test_professor_cannot_create_record_in_unassigned_course(client):
    """Variation: no existing row, so a patch that only guards the
    'update existing row' branch would still let the append through."""
    before = copy.deepcopy(api.GRADES)
    login(client, "prof_srs", "profpw")

    response = client.post(
        "/grades/update",
        json={"student_id": 1002, "course_id": "SSD", "grade": 20},
    )

    assert response.status_code == 403
    assert api.find_grade(1002, "SSD") is None
    assert api.GRADES == before


# --- Forbidden operations (read) --------------------------------------------

def test_student_cannot_read_another_students_grades(client):
    login(client, "alice", "alicepw")

    response = client.get("/grades/1002")

    assert response.status_code == 403
    assert b'"grade"' not in response.data


def test_professor_grade_list_is_filtered_to_assigned_courses(client):
    """Variation: a role-only check ("is a professor") passes this request,
    but the SSD row must not be disclosed (R3/R4 filtering)."""
    login(client, "prof_srs", "profpw")

    response = client.get("/grades/1001")

    assert response.status_code == 200
    rows = response.get_json()
    assert rows == [{"student_id": 1001, "course_id": "SRS", "grade": 14}]


def test_professor_denied_when_no_permitted_records(client):
    """R4: deny a request with no permitted records instead of returning
    other courses' grades."""
    api.GRADES[:] = [
        row for row in api.GRADES if not (row["student_id"] == 1002)
    ] + [{"student_id": 1002, "course_id": "SSD", "grade": 11}]
    login(client, "prof_srs", "profpw")

    response = client.get("/grades/1002")

    assert response.status_code == 403
    assert b"11" not in response.data


def test_unauthenticated_grade_read_is_rejected(client):
    response = client.get("/grades/1001")

    assert response.status_code == 401
    assert b'"grade"' not in response.data
