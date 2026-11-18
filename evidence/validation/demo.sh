#!/usr/bin/env bash
# Manual demonstration of the two selected vulnerabilities (V1 grade
# authorization, V2 path traversal) against the Docker image built from the
# current source.
#
# Run from the repository root (Git Bash):
#   bash evidence/validation/demo.sh before  # writes evidence/validation/manual-demo-before.txt
#   bash evidence/validation/demo.sh after   # after patching -> manual-demo-after.txt
set -u

LABEL="${1:-before}"
OUT="evidence/validation/manual-demo-${LABEL}.txt"
B=http://127.0.0.1:5001
NAME=secure-api-local
JAR="$(mktemp -d)"

start_api() {
  docker rm -f "$NAME" >/dev/null 2>&1
  docker run -d --name "$NAME" -p 127.0.0.1:5001:5001 "secure-coding-api:$LABEL" >/dev/null
  for _ in $(seq 1 20); do curl -s -o /dev/null "$B/" && return; sleep 1; done
  echo "API did not start"; docker logs "$NAME"; exit 1
}
login() { curl -s -o /dev/null -c "$JAR/$1" -X POST "$B/login" -d "username=$1" -d "password=$2"; }
step() { echo; echo "### $1"; echo "\$ $2"; }
req() { curl -s -i "$@" | tr -d '\r'; echo; }
json() { curl -s -i -X POST "$B/grades/update" -H "Content-Type: application/json" "$@" | tr -d '\r'; echo; }

{
echo "Manual vulnerability demonstration ($LABEL) - $(date -Iseconds)"
echo "Commit: $(git rev-parse --short HEAD)$(git diff --quiet -- baseline_secure_coding_api.py || echo ' + uncommitted changes')"

docker build -q -t "secure-coding-api:$LABEL" . >/dev/null || { echo "docker build failed"; exit 1; }
start_api
login alice alicepw; login prof_srs profpw; login admin1 adminpw

echo; echo "================ V1: Grade authorization (F04 + F05) ================"
step "Initial state (admin)" "GET /grades/1001 and /grades/1002"
req -b "$JAR/admin1" "$B/grades/1001"; req -b "$JAR/admin1" "$B/grades/1002"

step "V1.1 prof_srs (SRS only) reads student 1001 - expected 200 with SRS row only" "GET /grades/1001"
req -b "$JAR/prof_srs" "$B/grades/1001"
step "V1.2 prof_srs updates unassigned course SSD - expected 403" 'POST /grades/update {"student_id":1001,"course_id":"SSD","grade":0}'
json -b "$JAR/prof_srs" -d '{"student_id":1001,"course_id":"SSD","grade":0}'
step "V1.3 prof_srs creates record in unassigned course - expected 403" 'POST /grades/update {"student_id":1002,"course_id":"SSD","grade":20}'
json -b "$JAR/prof_srs" -d '{"student_id":1002,"course_id":"SSD","grade":20}'
step "V1.4 student alice changes own grade - expected 403" 'POST /grades/update {"student_id":1001,"course_id":"SRS","grade":20}'
json -b "$JAR/alice" -d '{"student_id":1001,"course_id":"SRS","grade":20}'
step "V1.5 student alice reads Bob's grades - expected 403" "GET /grades/1002"
req -b "$JAR/alice" "$B/grades/1002"
step "V1.6 unauthenticated update - expected 401" 'POST /grades/update {"student_id":1002,"course_id":"SRS","grade":0}'
json -d '{"student_id":1002,"course_id":"SRS","grade":0}'
step "V1.7 assigned professor updates SRS (legitimate) - expected 200" 'POST /grades/update {"student_id":1001,"course_id":"SRS","grade":18}'
json -b "$JAR/prof_srs" -d '{"student_id":1001,"course_id":"SRS","grade":18}'
step "Final state (admin) - expected: only SRS of 1001 changed to 18" "GET /grades/1001 and /grades/1002"
req -b "$JAR/admin1" "$B/grades/1001"; req -b "$JAR/admin1" "$B/grades/1002"

echo; echo "================ V2: Path traversal in /files (F08) ================"
start_api   # fresh container
login alice alicepw
step "V2.1 legitimate download - expected 200" "GET /files?path=srs-summary.txt"
req -b "$JAR/alice" -G "$B/files" --data-urlencode "path=srs-summary.txt"
step "V2.2 ../ traversal to application source - expected 400/403/404" "GET /files?path=../baseline_secure_coding_api.py (status + leaked secrets)"
curl -s -i -b "$JAR/alice" -G "$B/files" --data-urlencode "path=../baseline_secure_coding_api.py" | tr -d '\r' | grep -E "^HTTP|SECRET_KEY|password="; echo
step "V2.3 traversal mixed with a valid directory name - expected 400/403/404" "GET /files?path=../materials/../requirements.txt"
req -b "$JAR/alice" -G "$B/files" --data-urlencode "path=../materials/../requirements.txt"
step "V2.4 percent-encoded traversal - expected 400/403/404" "GET /files?path=%2e%2e%2frequirements.txt"
req -b "$JAR/alice" "$B/files?path=%2e%2e%2frequirements.txt"
step "V2.5 absolute path - expected 400/403/404" "GET /files?path=/etc/hostname"
# MSYS_NO_PATHCONV stops Git Bash on Windows rewriting /etc/hostname into a Windows path
MSYS_NO_PATHCONV=1 curl -s -i -b "$(cygpath -m "$JAR/alice" 2>/dev/null || echo "$JAR/alice")" \
  -G "$B/files" --data-urlencode "path=/etc/hostname" | tr -d '\r'; echo
step "V2.6 unauthenticated download - expected 401" "GET /files?path=../baseline_secure_coding_api.py (status + leaked secrets)"
curl -s -i -G "$B/files" --data-urlencode "path=../baseline_secure_coding_api.py" | tr -d '\r' | grep -E "^HTTP|SECRET_KEY|password="; echo
step "V2.7 missing file - expected 404 without internal path" "GET /files?path=nope.txt"
req -b "$JAR/alice" -G "$B/files" --data-urlencode "path=nope.txt"

docker rm -f "$NAME" >/dev/null 2>&1
} 2>&1 | tee "$OUT"

rm -rf "$JAR"
echo; echo "Saved to $OUT"
