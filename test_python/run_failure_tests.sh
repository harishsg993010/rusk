#!/bin/bash
RUSK="C:/Users/haris/Desktop/personal/rusk/target/release/rusk.exe"
PASS=0
FAIL=0
T=$(mktemp -d)

ok() { echo "  PASS"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "================================================"
echo "  rusk Failure Scenario Tests"
echo "================================================"

# --- INIT ---
echo ""
echo "--- INIT failures ---"

echo -n "init --ecosystem invalid: "
cd "$T" && mkdir t1 && cd t1
$RUSK init --ecosystem rust --name x 2>&1 | grep -qi "unknown\|invalid\|error" && ok || fail "accepted invalid ecosystem"

echo -n "init in dir with rusk.toml: "
cd "$T" && mkdir t2 && cd t2
$RUSK init --ecosystem js --name a 2>/dev/null
$RUSK init --ecosystem js --name b 2>&1 | grep -qi "exists\|already" && ok || fail "no duplicate warning"

# --- INSTALL ---
echo ""
echo "--- INSTALL failures ---"

echo -n "install empty dir (no manifest): "
cd "$T" && mkdir t3 && cd t3
$RUSK install 2>&1 | grep -qi "not found\|no.*found" && ok || fail "should error on no manifest"

echo -n "install nonexistent npm package: "
cd "$T" && mkdir t4 && cd t4
echo '{"name":"t","dependencies":{"zzz_nonexistent_pkg_12345":"1.0.0"}}' > package.json
$RUSK install 2>&1 | grep -qi "not found\|error\|failed" && ok || fail "should fail on fake package"

echo -n "install impossible version: "
cd "$T" && mkdir t5 && cd t5
echo '{"name":"t","dependencies":{"ms":"99999.0.0"}}' > package.json
$RUSK install 2>&1 | grep -qi "no version\|error\|failed" && ok || fail "should fail on impossible version"

echo -n "install empty deps succeeds: "
cd "$T" && mkdir t6 && cd t6
echo '{"name":"t","dependencies":{}}' > package.json
$RUSK install 2>&1 | grep -qi "error" && fail "should succeed" || ok

echo -n "install nonexistent Python package: "
cd "$T" && mkdir t7 && cd t7
echo "zzz_totally_fake_pkg_999>=1.0" > requirements.txt
$RUSK install 2>&1 | grep -qi "not found\|error\|failed" && ok || fail "should fail"

echo -n "install malformed package.json: "
cd "$T" && mkdir t8 && cd t8
echo '{broken' > package.json
$RUSK install 2>&1 | grep -qi "error\|failed\|parse" && ok || fail "should reject bad JSON"

echo -n "install malformed pyproject.toml: "
cd "$T" && mkdir t9 && cd t9
echo '[broken' > pyproject.toml
$RUSK install 2>&1 | grep -qi "error\|failed\|parse" && ok || fail "should reject bad TOML"

echo -n "install comments-only requirements.txt: "
cd "$T" && mkdir t10 && cd t10
printf "# comment\n# another\n" > requirements.txt
$RUSK install 2>&1 | grep -qi "error" && fail "should handle gracefully" || ok

# --- ADD ---
echo ""
echo "--- ADD failures ---"

echo -n "add with no args: "
$RUSK add 2>&1 | grep -qi "required\|error\|usage" && ok || fail "should require args"

echo -n "add creates manifest from nothing: "
cd "$T" && mkdir t11 && cd t11
$RUSK add ms@2.1.3 --ecosystem js 2>/dev/null
test -f package.json && ok || fail "should create package.json"

# --- REMOVE ---
echo ""
echo "--- REMOVE failures ---"

cd "$T" && mkdir t12 && cd t12
$RUSK init --ecosystem js --name rm 2>/dev/null
$RUSK add ms@2.1.3 2>/dev/null

echo -n "remove existing package: "
$RUSK remove ms 2>&1 | grep -qi "removed\|Removed" && ok || fail "should confirm removal"

echo -n "remove nonexistent package: "
$RUSK remove zzz_fake 2>&1 | grep -qi "not found\|warning\|no match\|could not" && ok || fail "should warn"

# --- VERIFY ---
echo ""
echo "--- VERIFY failures ---"

echo -n "verify with no lockfile: "
cd "$T" && mkdir t13 && cd t13
$RUSK init --ecosystem js --name vf 2>/dev/null
$RUSK verify 2>&1 | grep -qi "not found\|no lockfile\|error" && ok || fail "should fail without lockfile"

echo -n "verify tampered lockfile: "
cd "$T" && mkdir t14 && cd t14
echo '{"name":"t","dependencies":{"ms":"2.1.3"}}' > package.json
$RUSK install 2>/dev/null
sed -i 's/digest = "[a-f0-9]*/digest = "0000000000000000000000000000000000000000000000000000000000000000/' rusk.lock 2>/dev/null
$RUSK verify 2>&1 | grep -qi "FAIL\|not found\|failed\|mismatch" && ok || fail "should detect tamper"

# --- AUDIT ---
echo ""
echo "--- AUDIT failures ---"

cd "$T" && mkdir t15 && cd t15
$RUSK init --ecosystem js --name au 2>/dev/null
cat > rusk.toml << 'TOML'
[package]
name = "au"
version = "0.1.0"
ecosystem = "js"
[js_dependencies.dependencies]
ms = "2.1.3"
[js_dependencies.dev_dependencies]
[trust]
require_signatures = true
TOML
$RUSK install 2>/dev/null

echo -n "audit --strict exits nonzero for unsigned: "
$RUSK audit --strict 2>/dev/null
test $? -ne 0 && ok || fail "should exit nonzero"

# --- EXPLAIN ---
echo ""
echo "--- EXPLAIN failures ---"

echo -n "explain missing package: "
$RUSK explain zzz_fake 2>&1 | grep -qi "not found" && ok || fail "should say not found"

# --- TREE ---
echo ""
echo "--- TREE failures ---"

echo -n "tree with no lockfile: "
cd "$T" && mkdir t16 && cd t16
$RUSK tree 2>&1 | grep -qi "no lockfile\|not found\|install" && ok || fail "should warn no lockfile"

# --- RUN ---
echo ""
echo "--- RUN failures ---"

echo -n "run with no args: "
$RUSK run 2>&1 | grep -qi "required\|error\|usage" && ok || fail "should require args"

echo -n "run nonexistent script: "
cd "$T" && mkdir t17 && cd t17
echo '{"name":"t","dependencies":{}}' > package.json
$RUSK run node nonexistent.js 2>&1
test $? -ne 0 && ok || fail "should fail"

# --- LOCK ---
echo ""
echo "--- LOCK failures ---"

echo -n "lock with no manifest: "
cd "$T" && mkdir t18 && cd t18
$RUSK lock 2>&1 | grep -qi "not found\|error" && ok || fail "should fail"

# --- SYNC ---
echo ""
echo "--- SYNC removes stale ---"

cd "$T" && mkdir t19 && cd t19
echo '{"name":"t","dependencies":{"ms":"2.1.3"}}' > package.json
$RUSK install 2>/dev/null
mkdir -p node_modules/fake-stale
echo -n "sync removes stale package: "
$RUSK sync 2>&1 | grep -qi "Removed\|extraneous" && ok || fail "should remove stale"
test -d node_modules/fake-stale && fail "stale dir still exists" || true

# --- GC ---
echo ""
echo "--- GC ---"

cd "$T" && mkdir t20 && cd t20
$RUSK init --ecosystem js --name gc 2>/dev/null
$RUSK add ms@2.1.3 2>/dev/null
$RUSK remove ms 2>/dev/null
echo -n "gc finds unreferenced after remove: "
$RUSK gc --dry-run 2>&1 | grep -qi "Unreferenced\|would be\|reclaim" && ok || fail "should find unreferenced"

# --- VENV ---
echo ""
echo "--- VENV failures ---"

echo -n "venv with bad python: "
cd "$T" && mkdir t21 && cd t21
$RUSK venv .v --python nonexistent_python_999 2>&1 | grep -qi "error\|failed\|not found" && ok || fail "should fail"

# --- CAS CORRUPTION ---
echo ""
echo "--- CAS CORRUPTION ---"

cd "$T" && mkdir t22 && cd t22
echo '{"name":"t","dependencies":{"ms":"2.1.3"}}' > package.json
$RUSK install 2>/dev/null
DIGEST=$(grep 'digest = ' rusk.lock 2>/dev/null | head -1 | sed 's/.*"\(.*\)"/\1/')
if [ -n "$DIGEST" ]; then
    SHARD=$(echo $DIGEST | cut -c1-2)
    CAS=".rusk/cas/$SHARD/$DIGEST"
    if [ -f "$CAS" ]; then
        cp "$CAS" "$CAS.bak"
        echo "CORRUPT" > "$CAS"
        rm -rf node_modules .rusk/state.json .rusk/extracted
        echo -n "CAS corruption blocks install: "
        $RUSK install 2>&1 | grep -qi "integrity\|mismatch\|corrupt\|invalid\|error" && ok || fail "should detect corruption"
        cp "$CAS.bak" "$CAS"
        rm -f "$CAS.bak"
    else
        echo -n "CAS corruption: "; fail "CAS file not at expected path"
    fi
else
    echo -n "CAS corruption: "; fail "no digest in lockfile"
fi

# --- RESULTS ---
echo ""
echo "================================================"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "================================================"

rm -rf "$T"
exit $FAIL
