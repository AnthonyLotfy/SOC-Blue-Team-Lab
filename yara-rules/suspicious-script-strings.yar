/*
  Suspicious Script Strings - Educational YARA Rule

  Purpose:
  This rule looks for common suspicious script strings that may appear in
  obfuscated or risky PowerShell activity.

  This rule is for defensive education only. It does not contain malware,
  payloads, or exploit code.
*/

rule Suspicious_Script_Strings_Educational
{
    meta:
        description = "Detects suspicious script strings often seen in risky PowerShell activity"
        author = "SOC Blue Team Lab"
        date = "2026-07-12"
        usage = "Defensive education and lab testing only"

    strings:
        // PowerShell may use this option to run encoded content.
        $encoded_command = "EncodedCommand" nocase

        // This may indicate an attempt to avoid local execution policy restrictions.
        $execution_policy_bypass = "ExecutionPolicy Bypass" nocase

        // This string may indicate Base64 decoding inside a script.
        $from_base64 = "FromBase64String" nocase

        // IEX is a common alias for Invoke-Expression.
        $iex = "IEX" nocase

        // This string may indicate script content being downloaded as text.
        $download_string = "DownloadString" nocase

    condition:
        2 of them
}
