# Sentinel-Ransomware-Threat-Hunt--Want_To_Cry

Platform: Microsoft Sentinel + Microsoft Defender
Environment: Azure VM Lab
Focus: Ransomware Detection & Threat Hunting

## Overview
Defender Alert ID:
da2bdae3aa-7164-46ac-825d-52fcdd278972_1 & daa9f04e81-d68b-4275-a4c7-3cfb1e3d49d8_1

Defender Incident:
25780 & 25780

During routine threat hunting within an internet-connected cyber-range environment, Microsoft Defender for Endpoint triggered a behavioral detection:

Behavior:Win32/Ransomware!Note.G

The detection occurred on host:

vm-final-lab-wo

Defender attributed the activity to:

ntoskrnl.exe (PID 4)

which indicates that the file writes were performed through kernel filesystem operations.

The goal of this investigation was to determine:

What process triggered the ransomware-style behavior

Whether file encryption occurred

Whether the system was actively compromised

Whether the activity represented a real attack or a simulation

## Initial Detection

Defender behavioral monitoring detected rapid deployment of ransom-note style files across many directories.

Detection Details

Field	Value
Alert	Behavior:Win32/Ransomware!Note.G
Device	vm-final-lab-wo
Attributed Process	ntoskrnl.exe
Detection Type	Behavioral Monitoring

This rule triggers when Defender observes:

rapid ransom-note deployment
across multiple directories
within a short time window
## Investigation Timeline

The first step was identifying the exact time window of the activity.

Query – Identify First and Last Ransom Note
DeviceFileEvents
| where FileName == "!want_to_cry.txt"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count()
Result
First Seen	Last Seen	Count
08:48:08	08:48:25	270
Key Finding
Ransom notes were deployed across the filesystem within 17 seconds

This indicates automated directory recursion.

## File System Activity

Next, the overall file activity during the burst was analyzed.

Query – File Operations
DeviceFileEvents
| where Timestamp between (datetime(2026-03-02 08:47:30) .. datetime(2026-03-02 08:49:00))
| summarize count() by ActionType
Result
Action	Count
FileCreated	287
FileModified	146
FileRenamed	33
FileDeleted	41
Observation

The system performed:

287 file creations
378 directories touched

within a 17-second window.

This behavior strongly indicates:

recursive directory traversal

commonly used in ransomware.

## Process Attribution Challenge

Defender attributed the file writes to:

ntoskrnl.exe
PID 4

This occurs when file operations are executed through Windows kernel APIs such as:

CreateFile()
WriteFile()
MoveFile()

In these cases the originating user process may not appear in telemetry.

## Identifying Non-Kernel Processes

To locate potential parent processes, a correlation search was performed.

Query – File Touch Correlation
let t0 = datetime(2026-03-02 08:48:08);

DeviceFileEvents
| where Timestamp between (t0 - 30s .. t0 + 30s)
| summarize count() by InitiatingProcessFileName
| order by count_ desc
Result
Process	File Touches
ntoskrnl.exe	253
setup.exe	1
gc_worker.exe	1

## Process Investigation
setup.exe

Path:

C:\Program Files (x86)\Microsoft\EdgeWebView\Application\...\Installer\setup.exe

Command line:

--msedgewebview --delete-old-versions --system-level

Parent process:

runonce.exe
Conclusion

This was confirmed to be a legitimate Microsoft Edge WebView update process.

Additionally, the process executed 9 minutes after the ransomware activity, eliminating it as a possible origin.

gc_worker.exe

This process belongs to the Chromium / Edge runtime environment.

These worker processes do not perform recursive filesystem enumeration.

Conclusion

The process was incidental and unrelated to the event.

## Script Activity

Shortly after the ransom note deployment, PowerShell executed a script:

C:\Users\vm-final-lab-wo\Desktop\cypher-toggle.ps1

Execution time:

08:48:41

An additional artifact was observed:

__PSScriptPolicyTest_*.ps1

These temporary scripts are created when PowerShell verifies execution policy before running a script.

Significance

Although the script executed after the ransom-note deployment, it remains notable because:

it resides on a user desktop

the name references encryption (cypher)

it executed immediately after the event

Without access to the endpoint filesystem, the contents of the script could not be verified.

## Ransom Note Artifact

All notes were named:

!want_to_cry.txt

This name is an obvious reference to the WannaCry ransomware family.

However, real-world ransomware typically uses names such as:

README.txt
RECOVER_FILES.txt
HOW_TO_DECRYPT.txt

The humorous naming pattern suggests the possibility of:

security testing
cyber-range simulation
proof-of-concept tooling

## Encryption Analysis

A critical step was determining whether file encryption occurred.

Query – File Renames
DeviceFileEvents
| where ActionType == "FileRenamed"
| where Timestamp between (datetime(2026-03-02 08:47:30) .. datetime(2026-03-02 08:50:00))
| project Timestamp, PreviousFileName, FileName
Result

Only 33 rename operations were observed.

Typical ransomware encryption would produce:

thousands of renames
mass extension changes

Examples:

file.docx → file.docx.locked
image.jpg → image.jpg.encrypted
Conclusion

No evidence of encryption activity was identified.

## Network Activity

Network telemetry was reviewed for evidence of command-and-control communication.

Query
DeviceNetworkEvents
| where Timestamp between (datetime(2026-03-02 08:45:00) .. datetime(2026-03-02 09:00:00))
Result
No suspicious network connections detected

No signs of:

payload downloads
C2 communication
data exfiltration

## Authentication Review

Logon activity during the investigation window was analyzed.

Query
DeviceLogonEvents
| where Timestamp between (datetime(2026-03-02 08:40:00) .. datetime(2026-03-02 09:00:00))
Result

No suspicious authentication events were detected.

Specifically, no evidence of:

RDP logons
SMB lateral movement
new account creation

## Key Findings

Confirmed:

Rapid ransom-note deployment across filesystem
Automated directory enumeration
Defender behavioral detection triggered

Not observed:

File encryption
Command-and-control traffic
Privilege escalation
Lateral movement
Persistence mechanisms

## Conclusion

The investigation confirmed that ransom-note style files were deployed across the system, triggering Defender's ransomware behavioral detection.

However:

No encryption behavior was observed
No attacker infrastructure communication occurred
No evidence of compromise was identified

The activity most closely resembles:

ransomware simulation
security testing
proof-of-concept script

Defender likely detected the behavior before encryption could begin, or the activity was intentionally generated within the cyber-range environment.

## MITRE ATT&CK Mapping
Technique	Description
T1486	Data Encrypted for Impact (behavioral precursor)
T1083	File and Directory Discovery
T1106	Native API
T1059.001	PowerShell

## Lessons Learned

This investigation highlights several important threat hunting principles:

## Kernel Attribution Pitfall

Defender may attribute file writes to:

ntoskrnl.exe

when the originating process uses kernel filesystem APIs.

## Behavioral Detection Value

Defender detected the activity before encryption began, demonstrating the value of behavior-based detections.

## Importance of Context

In cyber-range environments, artifacts that resemble real attacks may originate from:

training exercises
simulation tools
security testing scripts
Future Improvements

## Recommended follow-up actions:

Retrieve and analyze cypher-toggle.ps1

Verify Defender remediation actions taken

Search environment for additional ransom-note artifacts

Implement automated alerts for mass directory file creation

## Final Assessment
Impact: Low
Encryption: Not observed
Containment: Defender behavioral detection

The system does not appear to have experienced actual ransomware encryption, though the behavior closely mimicked early ransomware activity.
