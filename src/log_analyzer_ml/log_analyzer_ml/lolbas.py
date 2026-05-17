from __future__ import annotations

LOTL_TECHNIQUES: frozenset[str] = frozenset(
    {
        "T1027",
        "T1047",
        "T1053.005",
        "T1059",
        "T1059.001",
        "T1059.003",
        "T1059.005",
        "T1059.007",
        "T1105",
        "T1127",
        "T1127.001",
        "T1140",
        "T1197",
        "T1216",
        "T1216.001",
        "T1218",
        "T1218.001",
        "T1218.003",
        "T1218.004",
        "T1218.005",
        "T1218.007",
        "T1218.010",
        "T1218.011",
        "T1218.013",
        "T1218.014",
        "T1220",
        "T1490",
        "T1548.002",
    }
)

LOLBAS_CATALOG: dict[str, frozenset[str]] = {
    "bitsadmin.exe": frozenset({"T1197", "T1105"}),
    "certutil.exe": frozenset({"T1140", "T1105"}),
    "cmd.exe": frozenset({"T1059.003"}),
    "cmstp.exe": frozenset({"T1218.003"}),
    "comsvcs.dll": frozenset({"T1003.001"}),
    "control.exe": frozenset({"T1218"}),
    "cscript.exe": frozenset({"T1059.005", "T1059.007"}),
    "csc.exe": frozenset({"T1127"}),
    "dnscmd.exe": frozenset({"T1574"}),
    "esentutl.exe": frozenset({"T1105"}),
    "extexport.exe": frozenset({"T1574"}),
    "extrac32.exe": frozenset({"T1105"}),
    "findstr.exe": frozenset({"T1552.006"}),
    "finger.exe": frozenset({"T1105"}),
    "forfiles.exe": frozenset({"T1059.003"}),
    "ftp.exe": frozenset({"T1105"}),
    "hh.exe": frozenset({"T1218.001"}),
    "ie4uinit.exe": frozenset({"T1548.002"}),
    "installutil.exe": frozenset({"T1218.004"}),
    "mavinject.exe": frozenset({"T1218.013"}),
    "mmc.exe": frozenset({"T1218.014"}),
    "mshta.exe": frozenset({"T1218.005"}),
    "msbuild.exe": frozenset({"T1127.001"}),
    "msdt.exe": frozenset({"T1218.014"}),
    "msiexec.exe": frozenset({"T1218.007"}),
    "msxsl.exe": frozenset({"T1220"}),
    "odbcconf.exe": frozenset({"T1218.008"}),
    "pcalua.exe": frozenset({"T1218"}),
    "powershell.exe": frozenset({"T1059.001"}),
    "powershell_ise.exe": frozenset({"T1059.001"}),
    "pwsh.exe": frozenset({"T1059.001"}),
    "regasm.exe": frozenset({"T1218.009"}),
    "regsvcs.exe": frozenset({"T1218.009"}),
    "regsvr32.exe": frozenset({"T1218.010"}),
    "rundll32.exe": frozenset({"T1218.011"}),
    "schtasks.exe": frozenset({"T1053.005"}),
    "scrcons.exe": frozenset({"T1546.003"}),
    "sdbinst.exe": frozenset({"T1546.011"}),
    "vbc.exe": frozenset({"T1127"}),
    "vssadmin.exe": frozenset({"T1490"}),
    "wbadmin.exe": frozenset({"T1490"}),
    "wmic.exe": frozenset({"T1047", "T1220"}),
    "wscript.exe": frozenset({"T1059.005", "T1059.007"}),
    "xwizard.exe": frozenset({"T1574"}),
}


def is_lolbin(basename_or_original: str) -> bool:
    return basename_or_original.lower() in LOLBAS_CATALOG


def parent_technique(technique: str) -> str:
    return technique.split(".", 1)[0]


def technique_intersects_lotl(techniques: list[str] | tuple[str, ...]) -> bool:
    return any(t in LOTL_TECHNIQUES or parent_technique(t) in LOTL_TECHNIQUES for t in techniques)
