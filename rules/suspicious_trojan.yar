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

