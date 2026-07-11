# SOC Blue Team Lab

## Suspicious PowerShell Detection Lab

This repository is a beginner-friendly defensive cybersecurity lab focused on detecting and investigating suspicious PowerShell activity on a Windows endpoint.

The scenario is based on a fake but realistic Windows process creation event where `powershell.exe` runs with the following suspicious command-line options:

- `-NoProfile`
- `-ExecutionPolicy Bypass`
- `-EncodedCommand`

The goal is to show how a junior SOC Analyst, Blue Team Analyst, or Cybersecurity Analyst can detect the activity, investigate it, document findings, and map the behavior to MITRE ATT&CK.

## Why This Lab Matters

PowerShell is a legitimate Windows administration tool, but attackers may abuse it for execution, defense evasion, and obfuscation. SOC analysts often review PowerShell alerts because suspicious command-line arguments can indicate malicious or unauthorized activity.

This lab helps demonstrate practical security monitoring skills without using malware, harmful payloads, or private data.

## Skills Demonstrated

- Windows security event log analysis
- Process creation investigation
- Suspicious command-line detection
- Sigma rule writing
- Basic YARA rule writing
- MITRE ATT&CK mapping
- Incident documentation
- Alert triage and risk rating
- Defensive investigation workflow
- Clear technical reporting for SOC environments

## Tools and Concepts Used

- Windows Event ID 4688 process creation logs
- PowerShell command-line analysis
- Sigma detection rules
- YARA string matching
- MITRE ATT&CK
- Incident response lifecycle
- SOC analyst documentation
- Endpoint detection concepts

## Folder Structure

```text
SOC-Blue-Team-Lab/
├── README.md
├── incidents/
│   └── suspicious-powershell-incident.md
├── sigma-rules/
│   └── suspicious-powershell-encoded-command.yml
├── yara-rules/
│   └── suspicious-script-strings.yar
├── mitre-mapping/
│   └── suspicious-powershell-mitre.md
├── logs/
│   └── sample-windows-event-log.txt
└── screenshots/
    └── README.md
```

## Detection Scenario

A Windows endpoint generated a process creation event showing suspicious PowerShell execution. The command line included `-NoProfile`, `-ExecutionPolicy Bypass`, and `-EncodedCommand`.

These arguments can be suspicious because they may allow a script to run without loading the normal user profile, bypass local execution policy restrictions, and hide the real command through encoding.

## Detection Logic

The main detection idea is to alert when PowerShell runs with multiple suspicious command-line options.

The Sigma rule looks for:

- PowerShell process execution
- Encoded command usage
- Execution policy bypass
- NoProfile usage
- Optional hidden window style
- Suspicious script strings such as Base64 decoding or download commands

This type of rule should be tuned in a real environment because administrators and management tools may sometimes use PowerShell for legitimate automation.

## Investigation Workflow

1. Review the alert details and confirm the event source.
2. Identify the affected host and user account.
3. Review the full PowerShell command line.
4. Check the parent process that launched PowerShell.
5. Look for encoded or obfuscated content.
6. Search for related process events before and after the alert.
7. Check for network connections, file creation, scheduled tasks, or persistence indicators.
8. Determine whether the activity is authorized administration or suspicious behavior.
9. Document findings in an incident report.
10. Recommend containment, eradication, and recovery actions if needed.

## MITRE ATT&CK Mapping Summary

| Technique ID | Technique Name | Reason |
|---|---|---|
| T1059 | Command and Scripting Interpreter | PowerShell was used to execute commands. |
| T1059.001 | PowerShell | The observed process was `powershell.exe`. |
| T1027 | Obfuscated Files or Information | `-EncodedCommand` may hide the real command content. |
| T1562.001 | Impair Defenses: Disable or Modify Tools | `-ExecutionPolicy Bypass` may indicate defense evasion behavior, but it does not prove malware by itself. |

## Incident Response Summary

Recommended response actions include:

- Validate whether the activity was approved.
- Isolate the endpoint if malicious activity is suspected.
- Collect relevant logs and endpoint telemetry.
- Decode and review the encoded command in a controlled analysis environment.
- Review the affected user account for suspicious activity.
- Remove unauthorized scripts or persistence mechanisms.
- Reset credentials if account compromise is suspected.
- Improve monitoring for suspicious PowerShell usage.

## How to Use This Repo

1. Read the main scenario in this README.
2. Review the sample Windows event log in `logs/`.
3. Study the Sigma rule in `sigma-rules/`.
4. Review the YARA rule in `yara-rules/`.
5. Read the MITRE mapping in `mitre-mapping/`.
6. Use the incident report in `incidents/` as a documentation example.
7. Add screenshots later in the `screenshots/` folder.

## What I Learned

This lab helped me understand how SOC analysts review suspicious PowerShell activity, write detection logic, map behavior to MITRE ATT&CK, and document findings in a professional incident report.

## Resume Bullet Points

- Built a defensive SOC lab to detect suspicious PowerShell execution using Windows Event ID 4688 process creation logs.
- Created a Sigma detection rule for PowerShell commands using `-EncodedCommand`, `-ExecutionPolicy Bypass`, and `-NoProfile`.
- Wrote a professional incident report documenting alert details, investigation steps, MITRE ATT&CK mapping, and response recommendations.
- Developed a safe educational YARA rule to identify suspicious script strings commonly associated with obfuscated PowerShell activity.
- Mapped observed behavior to MITRE ATT&CK techniques including PowerShell, Command and Scripting Interpreter, Obfuscated Files or Information, and possible defense evasion behavior.

## Disclaimer

This repository is for defensive cybersecurity education only. It does not contain malware, exploit code, private data, or instructions to harm systems. All logs, hostnames, usernames, and activity are fictional and created for safe SOC analyst training.
