rule RoguePlanet_CVE_2026_50656_PrivEsc_Dropper {
    meta:
        description = "Detects binaries exhibiting RoguePlanet-style privilege escalation targeting Windows Defender (CVE-2026-50656)"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "critical"
        mitre       = "T1068, T1562.001, T1055, T1134"
        remediation = "Isolate host, revoke elevated tokens, apply Defender patch when available, review WdFilter/MsMpEng integrity"
    strings:
        // Defender process / service targets
        $defender_proc1  = "MsMpEng.exe"        nocase wide ascii
        $defender_proc2  = "MsMpEngCP.exe"      nocase wide ascii
        $defender_svc1   = "WdNisSvc"           nocase wide ascii
        $defender_svc2   = "WinDefend"          nocase wide ascii
        $defender_drv    = "WdFilter"           nocase wide ascii
        $defender_drv2   = "WdNisDrv"          nocase wide ascii

        // Privilege / token manipulation primitives
        $priv1  = "SeDebugPrivilege"            wide ascii
        $priv2  = "SeTcbPrivilege"              wide ascii
        $priv3  = "SeImpersonatePrivilege"      wide ascii
        $tok1   = "NtAdjustPrivilegesToken"     wide ascii
        $tok2   = "ZwSetInformationThread"      wide ascii
        $tok3   = "DuplicateTokenEx"            wide ascii

        // Defender-internal COM/RPC attack surface strings
        $com1   = "{2781761E-28E0-4109-99FE-B9D127C57AFE}" nocase ascii  // MpClient CLSID
        $com2   = "MpClient.dll"               nocase wide ascii
        $com3   = "mpengine.dll"               nocase wide ascii

        // Registry manipulation of Defender configuration
        $reg1   = "SOFTWARE\\Microsoft\\Windows Defender" nocase wide ascii
        $reg2   = "DisableAntiSpyware"         nocase wide ascii
        $reg3   = "DisableRealtimeMonitoring"  nocase wide ascii
        $reg4   = "ExclusionPath"              nocase wide ascii

        // Named pipe patterns used in Defender IPC
        $pipe1  = "\\\\.\\pipe\\MpWppPipe"     nocase wide ascii
        $pipe2  = "\\\\.\\pipe\\WdNisSvcPipe"  nocase wide ascii

        // Shellcode / injection markers common to LPE exploits
        $sc1    = { 48 31 C0 65 48 8B 40 60 48 8B 40 18 }  // PEB walk x64
        $sc2    = { 60 89 E5 31 D2 64 8B 52 30 }            // PEB walk x86
        $sc3    = { 48 8B C4 48 89 58 08 48 89 68 10 }      // typical x64 prologue in shellcode loaders

        // Anti-tamper / ELAM bypass indicators
        $elam1  = "WdBoot.sys"                 nocase wide ascii
        $elam2  = "EarlyLaunchApproved"        nocase wide ascii
        $elam3  = "ELAM"                        wide ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        (
            (
                (2 of ($defender_proc*, $defender_svc*, $defender_drv*)) and
                (2 of ($priv*, $tok*))
            ) or
            (
                1 of ($com*) and 1 of ($priv*, $tok*) and 1 of ($reg*)
            ) or
            (
                1 of ($pipe*) and 1 of ($tok*) and 1 of ($sc*)
            ) or
            (
                1 of ($elam*) and 2 of ($priv*, $tok*, $reg*)
            )
        )
}

rule RoguePlanet_CVE_2026_50656_Script_Stager {
    meta:
        description = "Detects PowerShell/batch stager scripts weaponising Defender privilege escalation (CVE-2026-50656 pre-patch indicator)"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "high"
        mitre       = "T1068, T1562.001, T1059.001, T1547.009"
        remediation = "Block script execution via ASR rules, enforce constrained language mode, deploy WDAC policy"
    strings:
        // PowerShell Defender tampering patterns
        $ps1  = "Set-MpPreference"             nocase ascii
        $ps2  = "Add-MpPreference"             nocase ascii
        $ps3  = "DisableRealtimeMonitoring"    nocase ascii
        $ps4  = "ExclusionPath"                nocase ascii
        $ps5  = "Uninstall-WindowsFeature"     nocase ascii
        $ps6  = "Stop-Service.*WinDefend"      nocase ascii
        $ps7  = "sc stop WinDefend"            nocase ascii

        // Token/privilege manipulation via PowerShell or cmd
        $tok1 = "AdjustTokenPrivileges"        nocase ascii
        $tok2 = "SeDebugPrivilege"             ascii
        $tok3 = "whoami /priv"                 nocase ascii
        $tok4 = "impersonat"                   nocase ascii

        // Download-and-execute patterns typical of staged exploits
        $dl1  = "DownloadFile"                 nocase ascii
        $dl2  = "IEX"                          ascii
        $dl3  = "Invoke-Expression"            nocase ascii
        $dl4  = "FromBase64String"             nocase ascii
        $dl5  = "WebClient"                    nocase ascii

        // Defender service/process kill via script
        $kill1 = "taskkill.*MsMpEng"          nocase ascii
        $kill2 = "net stop WinDefend"         nocase ascii
        $kill3 = "sc config WinDefend start=disabled" nocase ascii

        // Obfuscation markers
        $ob1  = { 22 20 2B 20 22 }             // " + " string concat obfuscation
        $ob2  = "[char]"                        nocase ascii
        $ob3  = "-join"                         nocase ascii
        $ob4  = "replace('"                     nocase ascii

    condition:
        filesize < 2MB and
        (
            (
                (2 of ($ps*)) and (1 of ($tok*, $dl*, $kill*))
            ) or
            (
                1 of ($kill*) and 2 of ($tok*)
            ) or
            (
                3 of ($ps*) and 2 of ($ob*)
            ) or
            (
                1 of ($dl*) and 1 of ($ps*) and 1 of ($ob*)
            )
        )
}

rule RoguePlanet_CVE_2026_50656_Memory_Artifact {
    meta:
        description = "Memory-resident RoguePlanet exploit artifact — injected into MsMpEng or svchost context; scan process memory dumps"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "critical"
        mitre       = "T1068, T1055.012, T1134.001"
        remediation = "Capture full memory dump, terminate suspect process, force Defender re-scan from clean state, apply patch"
    strings:
        // ROP gadget / shellcode nop sled patterns common in LPE exploits
        $nop1   = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $nop2   = { CC CC CC CC CC CC CC CC }   // int3 padding

        // Token stealing shellcode skeleton (x64)
        $steal1 = { 65 48 8B 04 25 88 01 00 00  // KPCR->CurrentThread
                    48 8B 80 B8 00 00 00          // ETHREAD->Process
                    48 8B 88 ?? 00 00 00 }        // EPROCESS->Token

        // SeDebugPrivilege enable pattern in shellcode
        $debug_priv = { 20 00 00 00 00 00 00 00 02 00 00 00 }  // LUID for SeDebugPrivilege

        // Defender module strings that should not appear outside its own process
        $str1   = "mpengine"          nocase wide ascii
        $str2   = "MpClient"          nocase wide ascii
        $str3   = "MsMpEng"           nocase wide ascii
        $str4   = "WdFilter"          nocase wide ascii

        // Common C2 callback strings embedded in staged payloads
        $c2_1   = "beacon"            nocase ascii
        $c2_2   = "implant"           nocase ascii
        $c2_3   = "stage2"            nocase ascii
        $c2_4   = "payload"           nocase ascii

        // Hallmarks of reflective DLL loading (post-exploit)
        $rdll1  = { 52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72 }  // "ReflectiveLoader"
        $rdll2  = "ReflectiveDLLInjection"    nocase ascii

    condition:
        (
            1 of ($steal1, $nop1, $nop2) and 1 of ($str*)
        ) or
        (
            $debug_priv and 1 of ($str*)
        ) or
        (
            1 of ($rdll*) and 1 of ($str*, $c2_*)
        ) or
        (
            2 of ($c2_*) and 2 of ($str*)
        )
}
