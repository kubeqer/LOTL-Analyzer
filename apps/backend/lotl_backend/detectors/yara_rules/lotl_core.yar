rule LOTL_Office_Spawns_Shell
{
    strings:
        $office1 = "winword.exe" nocase
        $office2 = "excel.exe" nocase
        $office3 = "powerpnt.exe" nocase
        $office4 = "outlook.exe" nocase
        $office5 = "onenote.exe" nocase
        $office6 = "msaccess.exe" nocase
        $office7 = "visio.exe" nocase
        $shell1 = "powershell.exe" nocase
        $shell2 = "pwsh.exe" nocase
        $shell3 = "cmd.exe" nocase
        $shell4 = "wscript.exe" nocase
        $shell5 = "cscript.exe" nocase
        $shell6 = "mshta.exe" nocase
        $shell7 = "rundll32.exe" nocase
        $shell8 = "regsvr32.exe" nocase
    condition:
        any of ($office*) and any of ($shell*)
}

rule LOTL_PowerShell_Encoded_With_Payload
{
    strings:
        $ps = "powershell" nocase
        $enc1 = " -e " nocase
        $enc2 = " -en " nocase
        $enc3 = " -enc " nocase
        $enc4 = " -enco " nocase
        $enc5 = " -encod " nocase
        $enc6 = " -encode " nocase
        $enc7 = " -encoded " nocase
        $enc8 = " -encodedcommand " nocase
        $enc9 = " -ec " nocase
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        $ps and any of ($enc*) and $b64
}

rule LOTL_PowerShell_Download_Cradle
{
    strings:
        $ps = "powershell" nocase
        $iex1 = "IEX" nocase fullword
        $iex2 = "Invoke-Expression" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Invoke-WebRequest" nocase
        $dl4 = "Net.WebClient" nocase
        $http = "http" nocase
    condition:
        $ps and any of ($iex*) and any of ($dl*) and $http
}

rule LOTL_Mshta_Remote_Or_Inline_Script
{
    strings:
        $m = "mshta" nocase
        $u1 = "http://" nocase
        $u2 = "https://" nocase
        $u3 = "javascript:" nocase
        $u4 = "vbscript:" nocase
    condition:
        $m and any of ($u*)
}

rule LOTL_Regsvr32_Squiblydoo
{
    strings:
        $r = "regsvr32" nocase
        $scrobj = "scrobj.dll" nocase
        $i = "/i:" nocase
        $http = "http" nocase
    condition:
        $r and $scrobj and $i and $http
}

rule LOTL_Regsvr32_Remote_SCT
{
    strings:
        $r = "regsvr32" nocase
        $sct = ".sct" nocase
        $http = "http" nocase
    condition:
        $r and $sct and $http
}

rule LOTL_Certutil_UrlCache_Download
{
    strings:
        $c = "certutil" nocase
        $urlcache = "-urlcache" nocase
        $force = "-f" nocase
        $http = "http" nocase
    condition:
        $c and $urlcache and $force and $http
}

rule LOTL_Certutil_Decode
{
    strings:
        $c = "certutil" nocase
        $dec1 = "-decode" nocase
        $dec2 = "-decodehex" nocase
    condition:
        $c and any of ($dec*)
}

rule LOTL_Bitsadmin_Transfer_Http
{
    strings:
        $b = "bitsadmin" nocase
        $t = "/transfer" nocase
        $http = "http" nocase
    condition:
        $b and $t and $http
}

rule LOTL_Wmic_Remote_Process_Create
{
    strings:
        $w = "wmic" nocase
        $node = "/node:" nocase
        $pcc = "process call create" nocase
    condition:
        $w and $node and $pcc
}

rule LOTL_Rundll32_Suspicious_Export
{
    strings:
        $r = "rundll32" nocase
        $a = "javascript:" nocase
        $b = "mshtml,RunHTMLApplication" nocase
        $c = "comsvcs.dll,MiniDump" nocase
        $d = "url.dll,OpenURL" nocase
        $e = "advpack.dll,LaunchINFSection" nocase
        $f = "shell32.dll,ShellExec_RunDLL" nocase
    condition:
        $r and any of ($a, $b, $c, $d, $e, $f)
}

rule LOTL_Schtasks_System_PowerShell
{
    strings:
        $s = "schtasks" nocase
        $create = "/create" nocase
        $ru = "/ru" nocase
        $sys = "system" nocase
        $ps = "powershell" nocase
    condition:
        $s and $create and $ru and $sys and $ps
}

rule LOTL_Schtasks_Remote_PowerShell
{
    strings:
        $s = "schtasks" nocase
        $remote = "/s " nocase
        $ps = "powershell" nocase
    condition:
        $s and $remote and $ps
}

rule LOTL_Renamed_PowerShell
{
    strings:
        $orig = "PowerShell.EXE" ascii fullword
        $legit_path = /[\\\/]powershell\.exe/i
        $legit_basename = "powershell.exe" ascii
    condition:
        $orig and not ($legit_path or $legit_basename)
}

rule LOTL_Renamed_Cmd
{
    strings:
        $orig = "Cmd.Exe" ascii fullword
        $legit_path = /[\\\/]cmd\.exe/i
        $legit_basename = "cmd.exe" ascii
    condition:
        $orig and not ($legit_path or $legit_basename)
}
