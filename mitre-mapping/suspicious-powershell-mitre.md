# MITRE ATT&CK Mapping: Suspicious PowerShell Activity

This document maps the lab scenario to relevant MITRE ATT&CK techniques. The mapping is based on a fake Windows process creation event involving suspicious PowerShell command-line options.

## T1059 - Command and Scripting Interpreter

**Technique ID:** T1059

**Technique Name:** Command and Scripting Interpreter

**Why It Applies:**  
The observed activity used a command-line interpreter to execute instructions on a Windows endpoint.

**Evidence From the Lab:**  
The process creation event shows `powershell.exe` being launched from `cmd.exe`.

**Defensive Recommendation:**  
Enable process creation logging, collect command-line arguments, and monitor unusual interpreter usage from user workstations.

## T1059.001 - PowerShell

**Technique ID:** T1059.001

**Technique Name:** PowerShell

**Why It Applies:**  
PowerShell was the specific scripting environment used in the observed event.

**Evidence From the Lab:**  
The new process was `powershell.exe`, and the command line included PowerShell options such as `-NoProfile` and `-EncodedCommand`.

**Defensive Recommendation:**  
Enable PowerShell logging where appropriate, including module logging, script block logging, and transcription for higher-risk systems.

## T1027 - Obfuscated Files or Information

**Technique ID:** T1027

**Technique Name:** Obfuscated Files or Information

**Why It Applies:**  
The `-EncodedCommand` option can hide the readable command content from plain command-line review.

**Evidence From the Lab:**  
The observed command line included `-EncodedCommand <redacted-encoded-training-content>`.

**Defensive Recommendation:**  
Alert on encoded PowerShell usage, decode suspicious commands in a safe analysis environment, and review related endpoint telemetry for follow-on behavior.

## T1562.001 - Impair Defenses: Disable or Modify Tools

**Technique ID:** T1562.001

**Technique Name:** Impair Defenses: Disable or Modify Tools

**Why It Applies:**  
The `-ExecutionPolicy Bypass` option may indicate an attempt to avoid local script execution policy restrictions. This can be related to defense evasion behavior, but it does not prove malware by itself.

**Evidence From the Lab:**  
The observed command line included `-ExecutionPolicy Bypass`.

**Defensive Recommendation:**  
Monitor for attempts to bypass execution policy, review whether the activity was authorized, and use endpoint controls that do not rely only on execution policy.

## Summary

The activity is mapped to execution, PowerShell usage, obfuscation, and possible defense evasion. These mappings help SOC analysts explain why the alert matters while avoiding unsupported claims. The observed command line is suspicious, but additional evidence is required before confirming malicious activity.
