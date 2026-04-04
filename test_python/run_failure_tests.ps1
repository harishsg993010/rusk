$RUSK = "C:\Users\haris\Desktop\personal\rusk\target\release\rusk.exe"
$PASS = 0
$FAIL = 0
$T = Join-Path $env:TEMP "rusk-bugbash-$(Get-Random)"
New-Item -ItemType Directory -Path $T -Force | Out-Null

function Test-Expect-Success($name, $sb) {
    Write-Host -NoNewline "  $name ... "
    try {
        $out = & $sb 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) { Write-Host "PASS" -ForegroundColor Green; $script:PASS++ }
        else { Write-Host "FAIL (exit $LASTEXITCODE)" -ForegroundColor Red; $out | Select-Object -First 2 | ForEach-Object { Write-Host "    $_" }; $script:FAIL++ }
    } catch { Write-Host "FAIL (exception)" -ForegroundColor Red; $script:FAIL++ }
}

function Test-Expect-Fail($name, $sb) {
    Write-Host -NoNewline "  $name ... "
    try {
        $out = & $sb 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { Write-Host "PASS (correctly failed)" -ForegroundColor Green; $script:PASS++ }
        else { Write-Host "FAIL (should have failed)" -ForegroundColor Red; $script:FAIL++ }
    } catch { Write-Host "PASS (exception)" -ForegroundColor Green; $script:PASS++ }
}

function Test-Expect-Output($name, $pattern, $sb) {
    Write-Host -NoNewline "  $name ... "
    try {
        $out = & $sb 2>&1 | Out-String
        if ($out -match $pattern) { Write-Host "PASS" -ForegroundColor Green; $script:PASS++ }
        else { Write-Host "FAIL (no match for '$pattern')" -ForegroundColor Red; $out.Substring(0, [Math]::Min(200, $out.Length)) | ForEach-Object { Write-Host "    $_" }; $script:FAIL++ }
    } catch { Write-Host "FAIL (exception: $_)" -ForegroundColor Red; $script:FAIL++ }
}

Write-Host "================================================"
Write-Host "  rusk Failure Scenario Tests (PowerShell)"
Write-Host "  Temp: $T"
Write-Host "================================================"

# =============================================
Write-Host "`n--- 1. INIT FAILURES ---"
# =============================================

$d = Join-Path $T "init-invalid"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Test-Expect-Fail "init --ecosystem rust (invalid)" { & $RUSK init --ecosystem rust --name bad }
Pop-Location

$d = Join-Path $T "init-dupe"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
& $RUSK init --ecosystem js --name first 2>&1 | Out-Null
Test-Expect-Fail "init when rusk.toml exists" { & $RUSK init --ecosystem js --name second }
Pop-Location

# =============================================
Write-Host "`n--- 2. INSTALL FAILURES ---"
# =============================================

$d = Join-Path $T "inst-empty"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Test-Expect-Fail "install empty dir (no manifest)" { & $RUSK install }
Pop-Location

$d = Join-Path $T "inst-fake-npm"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content package.json '{"name":"t","dependencies":{"zzz_nonexistent_pkg_12345":"1.0.0"}}'
Test-Expect-Fail "install nonexistent npm package" { & $RUSK install }
Pop-Location

$d = Join-Path $T "inst-bad-ver"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content package.json '{"name":"t","dependencies":{"ms":"99999.0.0"}}'
Test-Expect-Fail "install impossible version" { & $RUSK install }
Pop-Location

$d = Join-Path $T "inst-empty-deps"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content package.json '{"name":"t","dependencies":{}}'
Test-Expect-Success "install empty deps" { & $RUSK install }
Pop-Location

$d = Join-Path $T "inst-fake-py"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content requirements.txt "zzz_totally_fake_pkg_999>=1.0"
Test-Expect-Fail "install nonexistent Python package" { & $RUSK install }
Pop-Location

$d = Join-Path $T "inst-bad-json"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content package.json "{broken json"
Test-Expect-Fail "install malformed package.json" { & $RUSK install }
Pop-Location

$d = Join-Path $T "inst-bad-toml"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content pyproject.toml "[broken toml"
Test-Expect-Fail "install malformed pyproject.toml" { & $RUSK install }
Pop-Location

$d = Join-Path $T "inst-comments"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content requirements.txt "# just comments`n# nothing else"
Test-Expect-Success "install comments-only requirements.txt" { & $RUSK install }
Pop-Location

# =============================================
Write-Host "`n--- 3. ADD FAILURES ---"
# =============================================

$d = Join-Path $T "add-noargs"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Test-Expect-Fail "add with no args" { & $RUSK add }
Pop-Location

$d = Join-Path $T "add-creates"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Test-Expect-Success "add creates manifest" { & $RUSK add ms@2.1.3 --ecosystem js }
if (Test-Path package.json) { Write-Host "    (package.json created)" } else { Write-Host "    WARNING: no manifest created" }
Pop-Location

# =============================================
Write-Host "`n--- 4. REMOVE FAILURES ---"
# =============================================

$d = Join-Path $T "remove-test"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
& $RUSK init --ecosystem js --name rm 2>&1 | Out-Null
& $RUSK add ms@2.1.3 2>&1 | Out-Null

Test-Expect-Output "remove existing package" "Removed" { & $RUSK remove ms }
Test-Expect-Output "remove nonexistent warns" "not found|warning|could not|no match" { & $RUSK remove zzz_fake_pkg }
Pop-Location

# =============================================
Write-Host "`n--- 5. VERIFY FAILURES ---"
# =============================================

$d = Join-Path $T "verify-nolock"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
& $RUSK init --ecosystem js --name vf 2>&1 | Out-Null
Test-Expect-Fail "verify with no lockfile" { & $RUSK verify }
Pop-Location

$d = Join-Path $T "verify-tamper"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content package.json '{"name":"t","dependencies":{"ms":"2.1.3"}}'
& $RUSK install 2>&1 | Out-Null
(Get-Content rusk.lock) -replace 'digest = "[a-f0-9]+"', 'digest = "0000000000000000000000000000000000000000000000000000000000000000"' | Set-Content rusk.lock
Test-Expect-Output "verify detects tampered lockfile" "FAIL|not found|failed" { & $RUSK verify }
Pop-Location

# =============================================
Write-Host "`n--- 6. AUDIT FAILURES ---"
# =============================================

$d = Join-Path $T "audit-strict"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
& $RUSK init --ecosystem js --name au 2>&1 | Out-Null
@"
[package]
name = "au"
version = "0.1.0"
ecosystem = "js"
[js_dependencies.dependencies]
ms = "2.1.3"
[js_dependencies.dev_dependencies]
[trust]
require_signatures = true
"@ | Set-Content rusk.toml
& $RUSK install 2>&1 | Out-Null
Test-Expect-Fail "audit --strict catches unsigned" { & $RUSK audit --strict }
Pop-Location

# =============================================
Write-Host "`n--- 7. EXPLAIN FAILURES ---"
# =============================================

$d = Join-Path $T "explain-test"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content package.json '{"name":"t","dependencies":{"ms":"2.1.3"}}'
& $RUSK install 2>&1 | Out-Null
Test-Expect-Output "explain installed package" "ALLOW|Verdict|trusted" { & $RUSK explain ms }
Test-Expect-Output "explain missing package" "not found" { & $RUSK explain zzz_fake }
Pop-Location

# =============================================
Write-Host "`n--- 8. TREE FAILURES ---"
# =============================================

$d = Join-Path $T "tree-nolock"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Test-Expect-Output "tree with no lockfile" "no lockfile|not found|install" { & $RUSK tree }
Pop-Location

$d = Join-Path $T "tree-ok"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content package.json '{"name":"t","dependencies":{"ms":"2.1.3"}}'
& $RUSK install 2>&1 | Out-Null
Test-Expect-Output "tree shows packages" "ms" { & $RUSK tree }
Pop-Location

# =============================================
Write-Host "`n--- 9. RUN FAILURES ---"
# =============================================

$d = Join-Path $T "run-test"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Test-Expect-Fail "run with no args" { & $RUSK run }

Set-Content package.json '{"name":"t","dependencies":{"ms":"2.1.3"}}'
& $RUSK install 2>&1 | Out-Null
Set-Content ok.js 'console.log("run-ok")'
Test-Expect-Output "run valid script" "run-ok" { & $RUSK run node ok.js }

Test-Expect-Fail "run nonexistent file" { & $RUSK run node nonexistent.js }
Pop-Location

# =============================================
Write-Host "`n--- 10. LOCK/SYNC ---"
# =============================================

$d = Join-Path $T "lock-empty"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Test-Expect-Fail "lock with no manifest" { & $RUSK lock }
Pop-Location

$d = Join-Path $T "sync-test"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content package.json '{"name":"t","dependencies":{"ms":"2.1.3"}}'
& $RUSK install 2>&1 | Out-Null
New-Item -ItemType Directory "node_modules/fake-stale" -Force | Out-Null
Test-Expect-Output "sync removes stale" "Removed|extraneous" { & $RUSK sync }
if (Test-Path "node_modules/fake-stale") { Write-Host "    WARN: stale dir still exists" -ForegroundColor Yellow }
Pop-Location

# =============================================
Write-Host "`n--- 11. GC ---"
# =============================================

$d = Join-Path $T "gc-test"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
& $RUSK init --ecosystem js --name gc 2>&1 | Out-Null
& $RUSK add ms@2.1.3 2>&1 | Out-Null
& $RUSK remove ms 2>&1 | Out-Null
Test-Expect-Output "gc finds unreferenced" "Unreferenced|reclaim|would be" { & $RUSK gc --dry-run }
Pop-Location

# =============================================
Write-Host "`n--- 12. VENV ---"
# =============================================

$d = Join-Path $T "venv-bad"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Test-Expect-Fail "venv with bad python" { & $RUSK venv .v --python nonexistent_python_999 }
Pop-Location

$d = Join-Path $T "venv-ok"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Test-Expect-Success "venv creates .venv" { & $RUSK venv .venv }
if (Test-Path ".venv") { Write-Host "    (.venv created)" }
Pop-Location

# =============================================
Write-Host "`n--- 13. PYTHON CMD ---"
# =============================================

Test-Expect-Output "python list finds installations" "Python" { & $RUSK python list }

$d = Join-Path $T "pypin"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Test-Expect-Success "python pin writes file" { & $RUSK python pin 3.11 }
if (Test-Path ".python-version") { Write-Host "    (.python-version = $(Get-Content .python-version))" }
Pop-Location

# =============================================
Write-Host "`n--- 14. CAS CORRUPTION ---"
# =============================================

$d = Join-Path $T "cas-corrupt"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content package.json '{"name":"t","dependencies":{"ms":"2.1.3"}}'
& $RUSK install 2>&1 | Out-Null
$digest = (Select-String -Path rusk.lock -Pattern 'digest = "([a-f0-9]+)"' | Select-Object -First 1).Matches.Groups[1].Value
if ($digest) {
    $shard = $digest.Substring(0,2)
    $cas = ".rusk\cas\$shard\$digest"
    if (Test-Path $cas) {
        Copy-Item $cas "$cas.bak"
        Set-Content $cas "CORRUPTED"
        Remove-Item -Recurse -Force node_modules -ErrorAction SilentlyContinue
        Remove-Item -Force .rusk\state.json -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force .rusk\extracted -ErrorAction SilentlyContinue
        Test-Expect-Output "CAS corruption detected" "integrity|mismatch|corrupt|invalid|gzip" { & $RUSK install }
        Copy-Item "$cas.bak" $cas -Force
        Remove-Item "$cas.bak"
    } else { Write-Host "  CAS corruption: SKIP (file not at $cas)" }
} else { Write-Host "  CAS corruption: SKIP (no digest)" }
Pop-Location

# =============================================
Write-Host "`n--- 15. JSON OUTPUT ---"
# =============================================

$d = Join-Path $T "json-out"; New-Item -ItemType Directory $d -Force | Out-Null; Push-Location $d
Set-Content package.json '{"name":"t","dependencies":{"ms":"2.1.3"}}'
& $RUSK install 2>&1 | Out-Null
Test-Expect-Output "install --format json" "status|exit_code|resolved" { & $RUSK install --format json }
Pop-Location

# =============================================
Write-Host ""
Write-Host "================================================"
Write-Host "  RESULTS: $PASS passed, $FAIL failed" -ForegroundColor $(if ($FAIL -eq 0) { "Green" } else { "Yellow" })
Write-Host "================================================"

Remove-Item -Recurse -Force $T -ErrorAction SilentlyContinue
exit $FAIL
