/*
    Python Source Code Vulnerability Patterns
    Scans Python source files for common vulnerability patterns: SQL injection,
    command injection, hardcoded secrets, path traversal, and dangerous eval/exec.
    Designed for pre-commit scanning, code review automation, and SAST pipelines.

    Usage:
        yara rules/python_vuln_patterns.yar /path/to/codebase/
        yara -r rules/python_vuln_patterns.yar src/

    Author  : CyberYARA / AgentForge
    Date    : 2026-06-10
    Severity: varies per rule
    MITRE   : T1190 (Exploit Public-Facing Application)
*/

rule Python_SQLInjection {
    meta:
        description = "Python SQL query built via string formatting or concatenation — SQL injection risk"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "high"
        mitre       = "T1190"
        remediation = "Use parameterized queries: cursor.execute(sql, params)"

    strings:
        $fmt1 = /cursor\.execute\s*\(\s*['"].*%s/ nocase
        $fmt2 = /cursor\.execute\s*\(\s*f['"]/ nocase
        $fmt3 = /execute\s*\(\s*['"].*\+/ nocase
        $fmt4 = /execute\s*\(.*\.format\s*\(/ nocase

    condition:
        any of them
}


rule Python_CommandInjection {
    meta:
        description = "Python subprocess or os.system call with dynamic string input — command injection risk"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "high"
        mitre       = "T1059.004"
        remediation = "Pass arguments as a list to subprocess; avoid shell=True"

    strings:
        $sys1  = /os\.system\s*\(\s*f['"]/ nocase
        $sys2  = /os\.system\s*\(\s*['"].*\+/ nocase
        $sub1  = /subprocess\.(call|run|Popen|check_output)\s*\(\s*f['"]/ nocase
        $sub2  = /subprocess\.(call|run|Popen|check_output)\s*\(\s*['"].*\+/ nocase

    condition:
        any of them
}


rule Python_ShellTrue {
    meta:
        description = "subprocess call with shell=True — enables shell injection"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "medium"
        mitre       = "T1059.004"
        remediation = "Remove shell=True; pass command as a list of arguments"

    strings:
        $shell_true = /shell\s*=\s*True/ nocase

    condition:
        $shell_true
}


rule Python_HardcodedPassword {
    meta:
        description = "Hardcoded password or passwd variable in Python source"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "high"
        mitre       = "T1552.001"
        remediation = "Load credentials from environment variables or a secrets manager"

    strings:
        $pass1 = /password\s*=\s*['"][^'"]{4,}['"]/ nocase
        $pass2 = /passwd\s*=\s*['"][^'"]{4,}['"]/ nocase
        $pass3 = /pwd\s*=\s*['"][^'"]{4,}['"]/ nocase

    condition:
        any of them
}


rule Python_HardcodedSecret {
    meta:
        description = "Hardcoded API key, token, or secret in Python source"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "high"
        mitre       = "T1552.001"
        remediation = "Load secrets from environment variables or a vault at runtime"

    strings:
        $api_key = /api_key\s*=\s*['"][A-Za-z0-9+\/=_\-]{8,}['"]/ nocase
        $secret  = /secret\s*=\s*['"][A-Za-z0-9+\/=_\-]{8,}['"]/ nocase
        $token   = /token\s*=\s*['"][A-Za-z0-9+\/=_\-]{8,}['"]/ nocase
        $auth    = /auth\s*=\s*['"][A-Za-z0-9+\/=_\-]{8,}['"]/ nocase

    condition:
        any of them
}


rule Python_PathTraversal {
    meta:
        description = "Python file open with user-controlled or dynamic path — path traversal risk"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "medium"
        mitre       = "T1083"
        remediation = "Validate that resolved path starts with an expected base directory"

    strings:
        $open_fstr   = /open\s*\(\s*f['"]/ nocase
        $open_concat = /open\s*\(\s*['"].*\+/ nocase
        $open_req    = /open\s*\(\s*request\./ nocase
        $join_req    = /os\.path\.join\s*\([^)]*request\./ nocase

    condition:
        any of them
}


rule Python_DangerousEval {
    meta:
        description = "Python eval or exec with dynamic (non-literal) input — arbitrary code execution risk"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "high"
        mitre       = "T1059.006"
        remediation = "Avoid eval/exec; use ast.literal_eval for safe literal parsing"

    strings:
        $eval_var  = /\beval\s*\(\s*(?!['"]\s*\))/ nocase
        $exec_var  = /\bexec\s*\(\s*(?!['"]\s*\))/ nocase

    condition:
        any of them
}


rule Python_MultipleVulns_HighConfidence {
    meta:
        description = "Python file contains multiple vulnerability classes — high-risk codebase"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-10"
        severity    = "critical"
        mitre       = "T1190, T1059"

    strings:
        $sql     = /cursor\.execute\s*\(\s*f['"]/ nocase
        $cmd     = /subprocess.*shell\s*=\s*True/ nocase
        $secret  = /password\s*=\s*['"][^'"]{4,}['"]/ nocase
        $eval_d  = /\beval\s*\(\s*(?!['"]\s*\))/ nocase

    condition:
        2 of them
}
