# Sentinel Ransomware Threat Hunt – Want_To_Cry

Platform: Microsoft Sentinel + Microsoft Defender  
Environment: Azure VM Lab  
Focus: Ransomware Detection & Threat Hunting  

---

# Executive Summary

During routine threat hunting within an internet-connected cyber-range environment, Microsoft Defender for Endpoint generated a behavioral detection indicating potential ransomware activity.

Detection:

```
Behavior:Win32/Ransomware!Note.G
```

Host affected:

```
vm-final-lab-wo
```

Defender attributed the activity to:

```
ntoskrnl.exe (PID 4)
```

This attribution indicates the file writes were executed through Windows kernel filesystem APIs.

The objective of this investigation was to determine:

- What process triggered the ransomware-style behavior
- Whether file encryption occurred
- Whether the system was actively compromised
- Whether the activity represented a real attack or a simulation

---

# Detection Details

| Field | Value |
|------|------|
| Alert | Behavior:Win32/Ransomware!Note.G |
| Device | vm-final-lab-wo |
| Process | ntoskrnl.exe |
| Detection Type | Behavioral Monitoring |

Defender triggers this rule when it observes:

- rapid ransom-note deployment  
- across many directories  
- within a short period of time  

---

# Investigation Timeline

The first step was identifying the exact time window of the activity.

## Query – Identify First and Last Ransom Note

```
DeviceFileEvents
| where FileName == "!want_to_cry.txt"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count()
```

## Result

| First Seen | Last Seen | Count |
|-----------|-----------|------|
| 08:48:08 | 08:48:25 | 270 |

### Key Finding

Ransom notes were deployed across the filesystem within **17 seconds**, indicating automated directory recursion.

---

# File System Activity

Next, the overall file activity during the burst was analyzed.

## Query – File Operations

```
DeviceFileEvents
| where Timestamp between (datetime(2026-03-02 08:47:30) .. datetime(2026-03-02 08:49:00))
| summarize count() by ActionType
```

## Result

| Action | Count |
|------|------|
| FileCreated | 287 |
| FileModified | 146 |
| FileRenamed | 33 |
| FileDeleted | 41 |

### Observation

Within **17 seconds** the system performed:

- 287 file creations  
- 378 directories touched  

This behavior strongly suggests:

```
recursive directory traversal
```

which is commonly used in ransomware.

---

# Process Attribution Challenge

Defender attributed the file writes to:

```
ntoskrnl.exe (PID 4)
```

This occurs when filesystem operations are executed through Windows kernel APIs such as:

- `CreateFile()`
- `WriteFile()`
- `MoveFile()`

In these situations, the originating user process may not appear in telemetry.

---

# Identifying Non-Kernel Processes

To locate potential parent processes, a correlation search was performed.

## Query – File Touch Correlation

```
let t0 = datetime(2026-03-02 08:48:08);

DeviceFileEvents
| where Timestamp between (t0 - 30s .. t0 + 30s)
| summarize count() by InitiatingProcessFileName
| order by count_ desc
```

## Result

| Process | File Touches |
|------|------|
| ntoskrnl.exe | 253 |
| setup.exe | 1 |
| gc_worker.exe | 1 |

---

# Process Investigation

## setup.exe

Path:

```
C:\Program Files (x86)\Microsoft\EdgeWebView\Application\...\Installer\setup.exe
```

Command Line:

```
--msedgewebview --delete-old-versions --system-level
```

Parent Process:

```
runonce.exe
```

### Conclusion

This was confirmed to be a legitimate **Microsoft Edge WebView update process**.

Additionally, the process executed **9 minutes after the ransomware event**, eliminating it as a possible origin.

---

## gc_worker.exe

This process belongs to the Chromium / Edge runtime environment.

These worker processes do not perform recursive filesystem enumeration.

### Conclusion

The process was incidental and unrelated to the event.

---

# Script Activity

Shortly after ransom-note deployment, PowerShell executed a script:

```
C:\Users\vm-final-lab-wo\Desktop\cypher-toggle.ps1
```

Execution time:

```
08:48:41
```

An additional artifact was observed:

```
__PSScriptPolicyTest_*.ps1
```

These files are temporary scripts created by PowerShell when validating execution policy before running a script.

### Significance

Although the script executed **after the ransom-note deployment**, it remains notable because:

- it resides on a user desktop  
- the name references encryption (`cypher`)  
- it executed immediately after the event  

Without filesystem access, the script contents could not be validated.

---

# Ransom Note Artifact

All notes were named:

```
!want_to_cry.txt
```

The name appears to reference the **WannaCry ransomware family**.

However, real ransomware typically uses names such as:

```
README.txt
RECOVER_FILES.txt
HOW_TO_DECRYPT.txt
```

### Interpretation

The naming pattern suggests the possibility of:

- security testing  
- cyber-range simulation  
- proof-of-concept tooling  

---

# Encryption Analysis

A critical step was determining whether file encryption occurred.

## Query – File Renames

```
DeviceFileEvents
| where ActionType == "FileRenamed"
| where Timestamp between (datetime(2026-03-02 08:47:30) .. datetime(2026-03-02 08:50:00))
| project Timestamp, PreviousFileName, FileName
```

## Result

Only **33 rename operations** were observed.

Typical ransomware encryption generates:

- thousands of renames
- widespread file extension changes

Examples:

```
file.docx → file.docx.locked
image.jpg → image.jpg.encrypted
```

### Conclusion

No evidence of large-scale encryption activity was observed.

---

# Network Activity

Network telemetry was reviewed for command-and-control communication.

## Query

```
DeviceNetworkEvents
| where Timestamp between (datetime(2026-03-02 08:45:00) .. datetime(2026-03-02 09:00:00))
```

### Result

No suspicious outbound connections were detected.

No evidence of:

- payload downloads  
- command-and-control communication  
- data exfiltration  

---

# Authentication Review

Authentication activity during the investigation window was reviewed.

## Query

```
DeviceLogonEvents
| where Timestamp between (datetime(2026-03-02 08:40:00) .. datetime(2026-03-02 09:00:00))
```

### Result

No suspicious authentication events were observed.

Specifically, there was no evidence of:

- RDP logons  
- SMB lateral movement  
- new account creation  

---

# Key Findings

Confirmed:

- Rapid ransom-note deployment across filesystem  
- Automated directory enumeration  
- Defender behavioral detection triggered  

Not observed:

- File encryption  
- Command-and-control traffic  
- Privilege escalation  
- Lateral movement  
- Persistence mechanisms  

---

# Conclusion

The investigation confirmed that ransom-note style files were deployed across the system, triggering Defender's ransomware behavioral detection.

However:

- No encryption activity was observed  
- No attacker infrastructure communication occurred  
- No evidence of system compromise was identified  

The activity most closely resembles:

- ransomware simulation  
- security testing  
- proof-of-concept scripting  

Defender likely detected the behavior **before encryption began**, or the activity was intentionally generated within the cyber-range environment.

---

# MITRE ATT&CK Mapping

| Technique | Description |
|------|------|
| T1486 | Data Encrypted for Impact (behavioral precursor) |
| T1083 | File and Directory Discovery |
| T1106 | Native API |
| T1059.001 | PowerShell |

---

# Lessons Learned

## Kernel Attribution Pitfall

Defender may attribute file writes to:

```
ntoskrnl.exe
```

when the originating process uses kernel filesystem APIs.

---

## Behavioral Detection Value

Defender detected suspicious activity **before encryption began**, demonstrating the value of behavior-based ransomware detection.

---

## Importance of Context

In cyber-range environments, artifacts that resemble real attacks may originate from:

- training exercises  
- simulation tools  
- security testing scripts  

---

# Future Improvements

Recommended follow-up actions:

- Retrieve and analyze `cypher-toggle.ps1`
- Verify Defender remediation actions
- Search the environment for additional ransom-note artifacts
- Implement alerts for rapid mass file creation

---

# Final Assessment

| Metric | Result |
|------|------|
| Impact | Low |
| Encryption | Not Observed |
| Containment | Defender Behavioral Detection |

The system does not appear to have experienced actual ransomware encryption, though the behavior closely mimicked early-stage ransomware activity.
