\# Testing



This lab was tested by checking whether the sample Windows Event ID 4688 log contains the suspicious PowerShell indicators used in the Sigma rule.



\## Test Command



```powershell

Select-String -Path .\\logs\\sample-windows-event-log.txt -Pattern "powershell.exe","-NoProfile","-ExecutionPolicy Bypass","-EncodedCommand"

```



\## Expected Result



The command should return matching lines containing:



\- powershell.exe

\- -NoProfile

\- -ExecutionPolicy Bypass

\- -EncodedCommand



\## Actual Result



The test returned matches from `logs/sample-windows-event-log.txt`.



Matched lines included:



```text

New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

Process Command Line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <redacted-encoded-training-content>

New Process: powershell.exe

```



\## Conclusion



The sample Windows Event ID 4688 log matches the suspicious PowerShell indicators used in the detection logic. This confirms that the lab evidence supports the Sigma rule and the incident report.

