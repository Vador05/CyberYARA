rule HAR_File_Generic {
    meta:
        description = "Detects HTTP Archive (HAR) files by their canonical JSON structure"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "low"
        mitre       = "T1005, T1074"
        remediation = "Review HAR file for sensitive data before sharing; HAR files capture full HTTP traffic including cookies, tokens, and POST bodies."
    strings:
        $har_log     = "\"log\""     ascii
        $har_entries = "\"entries\"" ascii
        $har_request = "\"request\"" ascii
        $har_response= "\"response\""ascii
        $har_version = "\"version\"" ascii
        $har_creator = "\"creator\"" ascii
    condition:
        $har_log and $har_entries and $har_request and $har_response and
        ($har_version or $har_creator)
}

rule HAR_Contains_Authorization_Header {
    meta:
        description = "Detects HAR files that capture Authorization headers (Bearer tokens, Basic auth credentials)"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "high"
        mitre       = "T1552, T1528"
        remediation = "Revoke exposed tokens/credentials immediately; do not store or transmit HAR files with Authorization headers in plaintext."
    strings:
        $har_entries   = "\"entries\""     ascii
        $auth_bearer   = "\"Bearer "       ascii nocase
        $auth_basic    = "\"Basic "        ascii nocase
        $auth_header   = "Authorization"   ascii nocase
        $token_header  = "X-Auth-Token"    ascii nocase
        $api_key_hdr   = "X-Api-Key"       ascii nocase
    condition:
        $har_entries and
        ($auth_bearer or $auth_basic or ($auth_header and 1 of ($auth_bearer,$auth_basic)) or $token_header or $api_key_hdr)
}

rule HAR_Contains_Session_Cookies {
    meta:
        description = "Detects HAR files capturing session or authentication cookies"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "high"
        mitre       = "T1539, T1552"
        remediation = "Invalidate captured session cookies; treat the HAR file as a credential leak and handle accordingly."
    strings:
        $har_entries  = "\"entries\""    ascii
        $cookie_hdr   = "\"Cookie\""     ascii nocase
        $set_cookie   = "\"Set-Cookie\"" ascii nocase
        $session_id   = "sessionid"      ascii nocase
        $jsessionid   = "JSESSIONID"     ascii nocase
        $phpsessid    = "PHPSESSID"      ascii nocase
        $asp_session  = "ASP.NET_SessionId" ascii nocase
        $auth_session = "auth_token"     ascii nocase
        $remember_me  = "remember_me"    ascii nocase
    condition:
        $har_entries and
        ($cookie_hdr or $set_cookie) and
        any of ($session_id, $jsessionid, $phpsessid, $asp_session, $auth_session, $remember_me)
}

rule HAR_Contains_Credentials_In_PostData {
    meta:
        description = "Detects HAR files with POST bodies containing password or credential fields"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "critical"
        mitre       = "T1552, T1078"
        remediation = "Change any exposed passwords immediately; treat HAR file as a credential dump and restrict access."
    strings:
        $har_postdata  = "\"postData\""   ascii
        $pwd_field     = "\"password\""   ascii nocase
        $pwd_field2    = "password="      ascii nocase
        $passwd_field  = "passwd="        ascii nocase
        $pass_field    = "\"pass\":"      ascii nocase
        $secret_field  = "\"secret\":"    ascii nocase
        $client_secret = "client_secret=" ascii nocase
        $api_key_param = "api_key="       ascii nocase
        $access_token  = "access_token="  ascii nocase
    condition:
        $har_postdata and
        any of ($pwd_field, $pwd_field2, $passwd_field, $pass_field, $secret_field, $client_secret, $api_key_param, $access_token)
}

rule HAR_Contains_OAuth_Tokens {
    meta:
        description = "Detects HAR files capturing OAuth2 access or refresh tokens in responses"
        author      = "CyberYARA / AgentForge"
        date        = "2026-06-18"
        severity    = "high"
        mitre       = "T1528, T1550.001"
        remediation = "Revoke captured OAuth tokens via the issuing provider; rotate client secrets if also present."
    strings:
        $har_entries    = "\"entries\""      ascii
        $access_token   = "\"access_token\"" ascii nocase
        $refresh_token  = "\"refresh_token\""ascii nocase
        $id_token       = "\"id_token\""     ascii nocase
        $token_type     = "\"token_type\""   ascii nocase
        $expires_in     = "\"expires_in\""   ascii nocase
    condition:
        $har_entries and
        ($access_token or $refresh_token or $id_token) and
        ($token_type or $expires_in)
}