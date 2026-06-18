rule Susp_VsCode_Extension_CredentialHarvest_JS {
    meta:
        description = "Detects JavaScript inside a VS Code extension (.vsix) that reads sensitive credential/key files and exfiltrates them via HTTP POST — classic supply-chain plugin backdoor"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "critical"
        mitre       = "T1195.001, T1552.001, T1005, T1071.001"
        remediation = "Quarantine the .vsix/extracted JS, rotate all credentials on the affected developer machine (SSH keys, AWS, GH tokens), audit egress logs for POSTs to unknown hosts"
    strings:
        // Credential file targets
        $cf_ssh_rsa    = ".ssh/id_rsa"         nocase
        $cf_ssh_ed     = ".ssh/id_ed25519"     nocase
        $cf_ssh_ecdsa  = ".ssh/id_ecdsa"       nocase
        $cf_aws        = ".aws/credentials"    nocase
        $cf_npmrc      = "/.npmrc"             nocase
        $cf_git_creds  = ".git-credentials"    nocase
        $cf_pypirc     = ".pypirc"             nocase

        // Env-var exfiltration targets
        $ev_aws_key    = "AWS_SECRET_ACCESS_KEY"  nocase
        $ev_gh_token   = "GITHUB_TOKEN"           nocase
        $ev_npm_token  = "NPM_TOKEN"              nocase
        $ev_all        = "process.env"

        // Read primitives
        $rd_sync       = "readFileSync"
        $rd_async      = "readFile("

        // Outbound POST sinks
        $post_fetch    = "method:\"POST\""
        $post_fetch2   = "method: \"POST\""
        $post_fetch3   = "method:'POST'"
        $post_fetch4   = "method: 'POST'"
        $post_axios    = "axios.post("
        $post_got      = "got.post("
        $post_node_h   = "require('https')"
        $post_node_h2  = "require(\"https\")"
        $post_node_h3  = "require('http')"
        $post_node_h4  = "require(\"http\")"
    condition:
        (
            (any of ($cf_*))
            and
            (any of ($rd_*))
            and
            (any of ($post_*))
        )
        or
        (
            ($ev_aws_key or $ev_gh_token or $ev_npm_token)
            and
            $ev_all
            and
            (any of ($post_*))
        )
}

rule Susp_VsCode_Extension_Obfuscated_Eval_Exec {
    meta:
        description = "Detects obfuscated payload execution in VS Code extension JS: eval/Function constructor over base64/hex decoded blobs, a hallmark of trojanized marketplace plugins"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "high"
        mitre       = "T1195.001, T1059.007, T1027"
        remediation = "Do not install or execute the extension; report the package to the marketplace; inspect the decoded payload for secondary indicators"
    strings:
        // Eval/dynamic execution sinks
        $ev1  = "eval("
        $ev2  = "new Function("
        $ev3  = "Function(\"return"
        $ev4  = "setTimeout(" nocase

        // Base64/hex decode sources paired with execution
        $dec1 = "atob("
        $dec2 = "Buffer.from("
        $dec3 = "'base64'"
        $dec4 = "\"base64\""
        $dec5 = ".toString('utf"
        $dec6 = ".toString(\"utf"
        $dec7 = "fromCharCode"

        // Process/shell spawning after decode
        $sh1  = "child_process"
        $sh2  = ".exec("
        $sh3  = ".execSync("
        $sh4  = ".spawn("
        $sh5  = "spawnSync("
    condition:
        (any of ($ev*))
        and
        (any of ($dec*))
        and
        (any of ($sh*))
}

rule Susp_Plugin_PackageJson_Typosquat_Publisher {
    meta:
        description = "Detects package.json files from VS Code extensions where the publisher field typosquats a known high-trust publisher (Microsoft, esLint, etc.) — indicative of a marketplace impersonation attack"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "medium"
        mitre       = "T1195.001, T1036.005"
        remediation = "Verify publisher identity on the official marketplace; compare publisher ID with the legitimate vendor's verified account; reject installation if mismatch found"
    strings:
        // Typosquats of Microsoft
        $pub_ms1  = "\"publisher\": \"Microsofft\""  nocase
        $pub_ms2  = "\"publisher\": \"Microssoft\""  nocase
        $pub_ms3  = "\"publisher\": \"MicrosoftCorp\"" nocase
        $pub_ms4  = "\"publisher\": \"ms-official\""  nocase

        // Typosquats of common high-volume publishers
        $pub_el1  = "\"publisher\": \"esllint\""      nocase
        $pub_el2  = "\"publisher\": \"esIint\""       nocase
        $pub_pr1  = "\"publisher\": \"prettierr\""    nocase
        $pub_pr2  = "\"publisher\": \"prettier-io\""  nocase
        $pub_db1  = "\"publisher\": \"dbaeumers\""    nocase
        $pub_db2  = "\"publisher\": \"dbaeumer0\""    nocase
        $pub_gk1  = "\"publisher\": \"eamodio-vsc\""  nocase
        $pub_gk2  = "\"publisher\": \"gitkraken-io\"" nocase

        // Implausibly broad permission scope in package.json
        $perm1    = "\"*\"" nocase
        $perm2    = "vscode.workspace.fs"
        $perm3    = "extensionKind"

        // Suspicious combined activation events
        $act1     = "\"*\""
        $act2     = "onStartupFinished"
    condition:
        (any of ($pub_*))
        or
        (
            (any of ($perm*))
            and
            (any of ($act*))
            and
            filesize < 50KB
        )
}

rule Susp_JetBrains_Plugin_RuntimeExec_Harvest {
    meta:
        description = "Detects JetBrains plugin source (Java/Kotlin) using Runtime.exec or ProcessBuilder to spawn shells and/or reading SSH/AWS credential paths — indicates a trojanized IntelliJ/PyCharm plugin"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "high"
        mitre       = "T1195.001, T1059.004, T1552.001"
        remediation = "Remove the plugin from the IDE immediately, revoke developer credentials, inspect process tree for spawned child processes during the period the plugin was active"
    strings:
        // Shell execution primitives
        $rt1  = "Runtime.getRuntime().exec("
        $rt2  = "new ProcessBuilder("
        $rt3  = "ProcessBuilder("
        $rt4  = "Runtime.exec("

        // Shell strings
        $sh1  = "\"/bin/sh\""
        $sh2  = "\"cmd.exe\""
        $sh3  = "\"/bin/bash\""
        $sh4  = "\"powershell\""  nocase

        // Credential file access patterns (Java string style)
        $cf1  = ".ssh/id_rsa"        nocase
        $cf2  = ".aws/credentials"   nocase
        $cf3  = ".git-credentials"   nocase
        $cf4  = "GITHUB_TOKEN"       nocase
        $cf5  = "AWS_SECRET"         nocase

        // Network exfiltration in Java
        $net1 = "HttpURLConnection"
        $net2 = "openConnection()"
        $net3 = "getOutputStream()"
        $net4 = "setRequestMethod(\"POST\")"
        $net5 = "OkHttpClient"
        $net6 = ".newCall("
    condition:
        (
            (any of ($rt*))
            and
            (any of ($sh*))
        )
        or
        (
            (any of ($cf*))
            and
            (any of ($net*))
        )
}