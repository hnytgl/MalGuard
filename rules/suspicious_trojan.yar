rule Suspicious_Trojan_Generic
{
    meta:
        description = "Generic suspicious Trojan markers for defensive triage"
        author = "MalGuard"
        scope = "defensive triage"
    strings:
        $inj1 = "CreateRemoteThread" ascii wide nocase
        $inj2 = "WriteProcessMemory" ascii wide nocase
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $svc1 = "CreateService" ascii wide nocase
        $acct1 = "net localgroup administrators" ascii wide nocase
        $linux1 = "/etc/systemd/system" ascii wide nocase
    condition:
        2 of them
}

rule SilverFox_Static_Markers
{
    meta:
        description = "SilverFox/Winos/ValleyRAT style loader, persistence, and staging markers"
        author = "MalGuard"
        scope = "defensive triage"
        reference = "Public SilverFox reports from QiAnXin and 360CERT"
    strings:
        $file1 = "insttect.exe" ascii wide nocase
        $file2 = "Microsoft.dll" ascii wide nocase
        $file3 = "monitor.bat" ascii wide nocase
        $file4 = "PolicyManagement.xml" ascii wide nocase
        $file5 = "target.pid" ascii wide nocase
        $task1 = ".NET Framework NGEN vTie" ascii wide nocase
        $ps1 = "Add-MpPreference" ascii wide nocase
        $ps2 = "ExclusionPath" ascii wide nocase
        $cmd1 = "regsvr32" ascii wide nocase
        $cfg1 = "Config.ini" ascii wide nocase
        $cfg2 = "Config2.ini" ascii wide nocase
        $exp1 = "VFPower" ascii wide nocase
        $rat1 = "Winos" ascii wide nocase
        $rat2 = "ValleyRAT" ascii wide nocase
        $port1 = ":18852" ascii wide
        $port2 = ":18853" ascii wide
        $port3 = ":9090" ascii wide
    condition:
        3 of ($file*) or
        all of ($ps*) or
        ($cmd1 and 1 of ($cfg*, $exp1, $task1)) or
        (1 of ($rat*) and 1 of ($port*))
}
