# Suspicious PowerShell Incident Report

## Executive Summary

A Windows endpoint generated a suspicious process creation event involving `powershell.exe`. The command line included `-NoProfile`, `-ExecutionPolicy Bypass`, and `-EncodedCommand`.

This behavior may indicate an attempt to run PowerShell with reduced restrictions and encoded content. The activity should be investigated to determine whether it was approved administrative activity or potentially malicious execution.

## Alert Overview

| Field | Value |
|---|---|
| Alert Name | Suspicious PowerShell Encoded Command |
| Severity | Medium |
| Confidence | Medium |
| Event Type | Process Creation |
| Event ID | 4688 |
| Status | Investigated |
| Environment | Training Lab |

## Affected Host

| Field | Value |
|---|---|
| Hostname | WIN-SOC-LAB-01 |
| Operating System | Windows 10 Enterprise |
| IP Address | 192.0.2.25 |
| User Account | LAB-USER01 |

The host, username, and IP address are fictional and used only for this lab.

## Event Source

- Source: Windows Security Event Log
- Event ID: 4688
- Event Description: A new process has been created
- Log Type: Endpoint process creation telemetry

## Detection Reason

The alert triggered because PowerShell was launched with multiple suspicious command-line options:

- `-NoProfile`
- `-ExecutionPolicy Bypass`
- `-EncodedCommand`

These options may be used by attackers to avoid normal PowerShell profile loading, bypass local execution policy settings, and obscure the command being executed.

## Timeline

| Time | Event |
|---|---|
| 2026-07-12 09:14:22 UTC | User session active on `WIN-SOC-LAB-01`. |
| 2026-07-12 09:15:08 UTC | `cmd.exe` launched `powershell.exe`. |
| 2026-07-12 09:15:08 UTC | PowerShell executed with suspicious command-line options. |
| 2026-07-12 09:16:30 UTC | SOC analyst reviewed the process creation event. |
| 2026-07-12 09:22:10 UTC | Activity documented and recommended for follow-up validation. |

## Observed Command Line

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <redacted-encoded-training-content>
```

The encoded content is redacted because this lab is defensive and does not include payloads or harmful code.

## Key Indicators

| Indicator Type | Value |
|---|---|
| Process Name | powershell.exe |
| Parent Process | cmd.exe |
| Command Option | -NoProfile |
| Command Option | -ExecutionPolicy Bypass |
| Command Option | -EncodedCommand |
| Hostname | WIN-SOC-LAB-01 |
| Username | LAB-USER01 |

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|---|---|---|
| T1059 | Command and Scripting Interpreter | PowerShell is a command and scripting interpreter. |
| T1059.001 | PowerShell | The observed process was `powershell.exe`. |
| T1027 | Obfuscated Files or Information | `-EncodedCommand` may hide the real command. |
| T1562.001 | Impair Defenses: Disable or Modify Tools | `-ExecutionPolicy Bypass` may indicate defense evasion behavior, but it does not prove malware by itself. |

## Risk Rating

**Medium**

The activity is suspicious because several risky PowerShell options were used together. The risk may increase to High if the encoded command is confirmed to download files, execute remote content, create persistence, or access sensitive data.

## Confidence

**Medium**

The alert has medium confidence because the command-line options are suspicious, but the available lab evidence does not confirm malware. Additional context, such as decoded command content, network activity, file changes, and user intent, would be needed before making a final determination.

## Analyst Investigation Steps

1. Confirmed that the event came from Windows Event ID 4688 process creation logging.
2. Reviewed the process name and command line.
3. Identified `cmd.exe` as the parent process.
4. Checked whether the user account was expected to run administrative PowerShell commands.
5. Reviewed the command-line options for obfuscation and defense evasion behavior.
6. Recommended decoding the encoded content only in a safe analysis environment.
7. Recommended searching for related process, file, registry, and network activity.
8. Documented findings and response recommendations.

## Containment Recommendations

- Validate whether the activity was authorized.
- Temporarily isolate the host if malicious activity is suspected.
- Disable or restrict the affected user account if compromise is suspected.
- Preserve relevant logs before making major system changes.
- Check for additional alerts involving the same user or host.

## Eradication Recommendations

- Remove unauthorized scripts or files identified during investigation.
- Remove suspicious scheduled tasks, services, or startup entries if found.
- Review PowerShell history and related command execution artifacts.
- Update endpoint protection tools and run a full scan.
- Reset credentials if the account shows signs of compromise.

## Recovery Recommendations

- Reconnect the endpoint only after suspicious activity is resolved.
- Confirm that normal business activity works as expected.
- Continue monitoring the host and user account for repeated PowerShell alerts.
- Review whether PowerShell logging and command-line auditing are enabled.
- Tune detections to reduce false positives while keeping useful visibility.

## Lessons Learned

- PowerShell command-line arguments can provide strong investigation clues.
- `-EncodedCommand` should be reviewed carefully because it can hide intent.
- Parent process context is important for understanding how PowerShell was launched.
- Clear documentation helps analysts explain risk and recommended response actions.
- Detection rules should balance useful alerts with expected administrative behavior.

## Final Conclusion

The observed PowerShell activity is suspicious and should be treated as a potential security event until validated. The command-line options suggest possible obfuscation and defense evasion behavior, but they do not confirm malware by themselves. No real malware or private data is included in this lab. The recommended next step is to validate business justification, review related endpoint activity, and apply containment if unauthorized behavior is confirmed.
