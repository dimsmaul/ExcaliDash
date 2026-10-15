#!/usr/bin/env bash
# Runs the Postgres-backed tests, one process per test.
#
# sqlx 0.8's `#[sqlx::test]` master pool (20 connections, shared per process) leaks
# its slots when each test's runtime shuts down, so after ~9 tests in one binary the
# rest fail with PoolTimedOut. One process per test sidesteps that.
#
# Usage: DATABASE_URL=postgres://postgres:postgres@localhost:5433/postgres scripts/test-db.sh
set -uo pipefail
cd "$(dirname "$0")/.."
: "${DATABASE_URL:?set DATABASE_URL to a Postgres superuser URL}"

pass=0
fail=0
for file in tests/*.rs; do
  bin=$(basename "$file" .rs)
  for name in $(cargo test -q --test "$bin" -- --ignored --list 2>/dev/null | sed -n 's/: test$//p'); do
    if cargo test -q --test "$bin" -- --ignored --exact "$name" >/dev/null 2>&1; then
      pass=$((pass + 1))
    else
      fail=$((fail + 1))
      echo "FAIL $bin::$name"
    fi
  done
done
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
