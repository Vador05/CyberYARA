rule DownloadDNSRecordsInCSVforADomain {
    meta:
        description = "Detects Python scripts that enumerate DNS record types and export results, matching the DownloadDNSRecordsInCSVforADomain tool pattern"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "low"
        mitre       = "T1590.002"
        remediation = "Review script intent; confirm authorized DNS inventory activity. Unauthorized DNS enumeration may indicate reconnaissance."
    strings:
        $lib_dnslib     = "import dnslib" nocase
        $lib_socket     = "import socket" nocase
        $record_a       = "'A'" nocase
        $record_aaaa    = "'AAAA'" nocase
        $record_cname   = "'CNAME'" nocase
        $record_mx      = "'MX'" nocase
        $record_ns      = "'NS'" nocase
        $record_txt     = "'TXT'" nocase
        $dns_question   = "DNSRecord.question" nocase
        $dns_parse      = "DNSRecord.parse" nocase
        $dns_send       = ".send(" nocase
        $google_dns     = "8.8.8.8"
        $csv_write      = "csv" nocase
        $rr_loop        = "response.rr" nocase
    condition:
        $lib_dnslib and
        $dns_question and
        $dns_parse and
        $rr_loop and
        3 of ($record_a, $record_aaaa, $record_cname, $record_mx, $record_ns, $record_txt)
}