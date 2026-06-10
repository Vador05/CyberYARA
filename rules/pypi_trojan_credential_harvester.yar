/*
    PyPI Supply Chain Trojan - Credential Harvesting Patterns
    Scans Python source files inside PyPI wheels (.whl) or extracted packages
    for patterns characteristic of credential-stealing trojans.

    Usage:
        yara rules/pypi_trojan_credential_harvester.yar /path/to/extracted/package/
        yara rules/pypi_trojan_credential_harvester.yar suspicious.py

    Author  : CyberYARA / AgentForge
    Date    : 2026-06-10
    Severity: HIGH
    MITRE   : T1195.001 (Supply Chain Compromise - Compromise Software Dependencies)
*/

rule PyPI_Trojan_EnvVar_Exfiltration {
    meta:
        description = "Python package reads sensitive environment variables for likely exfiltration"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "high"
        mitre       = "T1195.001, T1552.001"
        reference   = "https://attack.mitre.org/techniques/T1195/001/"

    strings:
        $env_aws     = /os\.environ\.get\s*\(\s*['"]AWS[^'"]*['"]/ nocase
        $env_secret  = /os\.environ\.get\s*\(\s*['"]SECRET[^'"]*['"]/ nocase
        $env_token   = /os\.environ\.get\s*\(\s*['"]TOKEN[^'"]*['"]/ nocase
        $env_api_key = /os\.environ\.get\s*\(\s*['"]API_KEY[^'"]*['"]/ nocase
        $env_pass    = /os\.environ\.get\s*\(\s*['"]PASSWORD[^'"]*['"]/ nocase
        $env_private = /os\.environ\.get\s*\(\s*['"]PRIVATE[^'"]*['"]/ nocase

    condition:
        any of them
}


rule PyPI_Trojan_HTTP_Exfiltration {
    meta:
        description = "Python package exfiltrates credentials via HTTP POST"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "critical"
        mitre       = "T1041, T1195.001"

    strings:
        $post1 = /requests\s*\.\s*post\s*\(.*(?:password|secret|token|credential)/ nocase
        $post2 = /urllib.*\.post\s*\(.*(?:password|secret|token|credential)/ nocase
        $post3 = /http\.request.*POST.*(?:password|secret|token)/ nocase

    condition:
        any of them
}


rule PyPI_Trojan_C2_Webhook {
    meta:
        description = "Python package sends data to Discord or Telegram webhook — common C2 in trojanized packages"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "critical"
        mitre       = "T1102.002, T1195.001"

    strings:
        $discord  = "discord.com/api/webhooks" nocase
        $discordapp = "discordapp.com/api/webhooks" nocase
        $telegram = "api.telegram.org/bot" nocase

    condition:
        any of them
}


rule PyPI_Trojan_Encoded_Payload {
    meta:
        description = "Python package executes base64-decoded or otherwise obfuscated payload"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "critical"
        mitre       = "T1027, T1195.001"

    strings:
        $b64_decode = /base64\.b64decode\s*\(\s*['"][A-Za-z0-9+\/]{20,}={0,2}['"]/ nocase
        $exec_b64   = /exec\s*\(\s*(?:base64|codecs|zlib)/ nocase
        $eval_b64   = /eval\s*\(\s*(?:base64|codecs|zlib)/ nocase

    condition:
        any of them
}


rule PyPI_Trojan_Subprocess_Download {
    meta:
        description = "Python package spawns curl or wget subprocess to download and execute remote content"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "high"
        mitre       = "T1059.004, T1195.001"

    strings:
        $sub_curl = /subprocess.*(?:curl|wget).*(?:http|ftp)/ nocase
        $sub_pipe = /subprocess.*[|>].*(?:sh|bash)/ nocase

    condition:
        any of them
}


rule PyPI_Trojan_Socket_Exfiltration {
    meta:
        description = "Python package connects raw socket to hardcoded IP — potential data exfiltration channel"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "high"
        mitre       = "T1041, T1195.001"

    strings:
        $socket_ip = /socket\.connect\s*\(\s*\(\s*['"][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}['"]/

    condition:
        $socket_ip
}


rule PyPI_Trojan_Exfil_Service {
    meta:
        description = "Python package uploads data to pastebin, hastebin, or ngrok tunnel"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "high"
        mitre       = "T1567, T1195.001"

    strings:
        $pastebin  = "pastebin.com" nocase
        $paste_ee  = "paste.ee" nocase
        $hastebin  = "hastebin.com" nocase
        $ngrok     = "ngrok.io" nocase
        $ngrok_free = ".ngrok-free.app" nocase

    condition:
        any of them
}


rule PyPI_Trojan_Combined_High_Confidence {
    meta:
        description = "High-confidence PyPI trojan: combines environment variable access with exfiltration channel"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "critical"
        mitre       = "T1195.001, T1552.001, T1041"

    strings:
        $env_access   = /os\.environ/ nocase
        $discord      = "discord.com/api/webhooks" nocase
        $telegram     = "api.telegram.org/bot" nocase
        $pastebin     = "pastebin.com" nocase
        $post_request = /requests\s*\.\s*post/ nocase

    condition:
        $env_access and (1 of ($discord, $telegram, $pastebin, $post_request))
}
