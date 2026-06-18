rule RoguePlanet_Exploit_Tool {
    meta:
        description = "Detects tools or scripts exploiting the RoguePlanet Defender race condition for SYSTEM shell escalation"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "critical"
        mitre       = "T1068, T1543.003, T1574.010, T1218"
        remediation = "Isolate host, revoke active sessions, apply Microsoft patch for RoguePlanet; audit process tree for children of MsMpEng.exe or MpCmdRun.exe spawning interactive shells"

    strings:
        // Explicit vulnerability branding in exploit tools
        $vname1  = "RoguePlanet"          nocase wide ascii
        $vname2  = "roguePlanet"          nocase wide ascii

        // Defender service / binary targets commonly abused in race-condition LPE against AV engines
        $def1    = "MsMpEng.exe"          nocase wide ascii
        $def2    = "MpCmdRun.exe"         nocase wide ascii
        $def3    = "MsMpSvc"              nocase wide ascii
        $def4    = "WinDefend"            nocase wide ascii
        $def5    = "\\Windows Defender\\" nocase wide ascii

        // Defender temp/quarantine paths manipulated during the race window
        $path1   = "\\MpCmdRun\\"         nocase wide ascii
        $path2   = "\\Quarantine\\"        nocase wide ascii
        $path3   = "\\CacheStore\\"        nocase wide ascii
        $path4   = "\\Scans\\History\\"    nocase wide ascii

        // Oplock / race-condition primitives used to win the race against privileged Defender threads
        $race1   = "NtSetSecurityObject"   nocase wide ascii
        $race2   = "CreateOplockRequest"   nocase wide ascii
        $race3   = "DeviceIoControl"       nocase wide ascii
        $race4   = "FSCTL_REQUEST_OPLOCK"  nocase wide ascii
        $race5   = "WaitForSingleObject"   nocase wide ascii

        // SYSTEM token / impersonation abuse after winning the race
        $sys1    = "ImpersonateNamedPipeClient" nocase wide ascii
        $sys2    = "SeDebugPrivilege"      nocase wide ascii
        $sys3    = "SeImpersonatePrivilege" nocase wide ascii
        $sys4    = "TokenImpersonation"    nocase wide ascii
        $sys5    = "DuplicateTokenEx"      nocase wide ascii
        $sys6    = "CreateProcessWithToken" nocase wide ascii

        // SYSTEM shell indicators in a Defender-privilege context
        $shell1  = "cmd.exe /c"            nocase wide ascii
        $shell2  = "powershell -enc"       nocase wide ascii
        $shell3  = "powershell -nop"       nocase wide ascii
        $shell4  = "powershell -w hidden"  nocase wide ascii
        $shell5  = "NT AUTHORITY\\SYSTEM"  nocase wide ascii
        $shell6  = "whoami /all"           nocase wide ascii

        // Symlink / junction tricks used by LotL race exploits to redirect Defender writes
        $link1   = "CreateSymbolicLink"    nocase wide ascii
        $link2   = "SYMBOLIC_LINK_FLAG"    nocase wide ascii
        $link3   = "NtCreateSymbolicLinkObject" nocase wide ascii
        $link4   = "SetReparsePoint"       nocase wide ascii

    condition:
        // Executable or script (PE, PS1, Python, batch — broad filesize guard)
        filesize < 20MB and
        (
            // Named vulnerability present alongside any exploitation primitive
            (
                any of ($vname*) and
                (any of ($race*) or any of ($sys*) or any of ($link*))
            )
            or
            // Defender target + race primitive + privilege-escalation chain
            (
                any of ($def*) and
                any of ($race*) and
                (any of ($sys*) or any of ($link*))
            )
            or
            // Defender path manipulation + SYSTEM shell spawning combo
            (
                any of ($path*) and
                any of ($shell*) and
                any of ($sys*)
            )
            or
            // Broad: explicit SYSTEM authority string alongside Defender service reference
            (
                $shell5 and any of ($def*)
            )
        )
}

rule RoguePlanet_PowerShell_Stager {
    meta:
        description = "Detects PowerShell scripts staging the RoguePlanet Defender race-condition LPE payload"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "high"
        mitre       = "T1059.001, T1068, T1055, T1543.003"
        remediation = "Block execution, inspect ScriptBlock logs (Event 4104), hunt for child processes of Defender services, patch host"

    strings:
        $ps_enc1  = "FromBase64String"   nocase ascii wide
        $ps_enc2  = "-EncodedCommand"    nocase ascii wide
        $ps_enc3  = "IEX"               nocase ascii wide
        $ps_enc4  = "Invoke-Expression" nocase ascii wide

        $def_svc  = "WinDefend"         nocase ascii wide
        $def_bin  = "MsMpEng"           nocase ascii wide
        $def_cmd  = "MpCmdRun"          nocase ascii wide

        $priv1    = "SeImpersonatePrivilege" nocase ascii wide
        $priv2    = "whoami"                 nocase ascii wide
        $priv3    = "NT AUTHORITY"           nocase ascii wide

        $race_ps1 = "Start-Job"         nocase ascii wide
        $race_ps2 = "RunspaceFactory"   nocase ascii wide
        $race_ps3 = "Thread"            nocase ascii wide

        $lolbin1  = "certutil"          nocase ascii wide
        $lolbin2  = "msiexec"           nocase ascii wide
        $lolbin3  = "wmic"              nocase ascii wide
        $lolbin4  = "regsvr32"          nocase ascii wide
        $lolbin5  = "rundll32"          nocase ascii wide

    condition:
        filesize < 5MB and
        (
            // Obfuscated PS + Defender service targeting
            (
                any of ($ps_enc*) and
                (any of ($def_svc, $def_bin, $def_cmd))
            )
            or
            // Race-aware PS threading + Defender + privilege string
            (
                any of ($race_ps*) and
                any of ($def_svc, $def_bin, $def_cmd) and
                any of ($priv*)
            )
            or
            // LOLBin chaining with Defender context and privilege escalation marker
            (
                any of ($lolbin*) and
                any of ($def_svc, $def_bin, $def_cmd) and
                any of ($priv*)
            )
        )
}

rule RoguePlanet_DroppedSYSTEM_Shell_Artifact {
    meta:
        description = "Detects artifacts (scripts, executables) written to disk by a SYSTEM-context Defender process as part of RoguePlanet post-exploitation"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "critical"
        mitre       = "T1068, T1105, T1036.005, T1218"
        remediation = "Immediately quarantine file, collect memory dump of parent process, revoke SYSTEM sessions, escalate to IR"

    strings:
        // Reverse-shell / C2 callback strings often present in SYSTEM-context drops
        $rc1  = "socket.connect"       nocase ascii wide
        $rc2  = "TCPClient"            nocase ascii wide
        $rc3  = "WebClient"            nocase ascii wide
        $rc4  = "DownloadString"       nocase ascii wide
        $rc5  = "Net.Sockets.TcpClient" nocase ascii wide
        $rc6  = "StreamReader"         nocase ascii wide

        // Post-exploitation framework indicators
        $fw1  = "meterpreter"          nocase ascii wide
        $fw2  = "CobaltStrike"         nocase ascii wide
        $fw3  = "cobaltstrike"         nocase ascii wide
        $fw4  = "Sliver"               nocase ascii wide
        $fw5  = "Havoc"                nocase ascii wide
        $fw6  = "SILENTTRINITY"        nocase ascii wide

        // RoguePlanet / generic exploit branding
        $tag1 = "RoguePlanet"          nocase ascii wide
        $tag2 = "roguePlanet"          nocase ascii wide
        $tag3 = "DefenderRace"         nocase ascii wide
        $tag4 = "MpLPE"               nocase ascii wide

        // SYSTEM-confirmation strings embedded by exploit authors for logging
        $sys1 = "NT AUTHORITY\\SYSTEM" nocase ascii wide
        $sys2 = "SYSTEM shell"         nocase ascii wide
        $sys3 = "Got SYSTEM"           nocase ascii wide
        $sys4 = "elevated to SYSTEM"   nocase ascii wide

    condition:
        filesize < 10MB and
        (
            any of ($tag*) or
            any of ($sys2, $sys3, $sys4) or
            (
                $sys1 and any of ($rc*)
            ) or
            (
                any of ($fw*) and $sys1
            )
        )
}