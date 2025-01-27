<img width="400" src="https://github.com/user-attachments/assets/8c336c48-6bc5-428c-b4be-8af9575c9a83" alt="Computer with 'RDP' on it."/>

# Threat Hunt Report: Unauthorized RDP Access
- [Scenario Creation](https://github.com/Goodka7/Threat-Hunting-RDP-/blob/main/resources/Threat-Hunt-Event(RDP).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Nmap
- RDP

##  Scenario

Management has expressed concern over unauthorized access through Remote Desktop Protocol (RDP), which could compromise system integrity and security. Recent observations suggest irregular login patterns and the potential for malicious activity following RDP sessions, including actions such as privilege escalation and system reconnaissance. Management has given one machine that they believe might be compromised (THScenarioVM "10.0.0.26").

The objective is to identify unauthorized RDP access, analyze any suspicious behaviors during and after remote sessions, and detect Indicators of Compromise (IOCs) that may indicate further security risks. Immediate action will be taken to address any identified threats.

### High-Level RDP-Related IoC Discovery Plan

- **Check `DeviceLogonEvents`** for irregular RDP logins, particularly focusing on successful logins from external or suspicious IP addresses.
- **Check `DeviceProcessEvents`** to identify processes initiated during RDP sessions, such as commands executed via `cmd.exe` or `powershell.exe`, and any creation of new user accounts.
- **Check `DeviceNetworkEvents`**:  to investigate outbound connections initiated during or after the RDP session, which may indicate data exfiltration or communication with attacker-controlled systems.

---

## Steps Taken

### 1. Searched the `DeviceLogonEvents` Table

Searched for any logon activity related to RDP connections with the action type "LogonSuccess" or "LogonFailed".

The dataset reveals multiple logon events originating from the device "thscenariovm" that align with concerns about unauthorized RDP access. On **Jan 27, 2025, at 3:29:12 PM**, a `RemoteInteractive` logon was successfully executed by the account `labuser`, originating from the IP address `10.0.8.5`. This event represents a direct RDP session initiation.

Additionally, a `Network` logon type on **Jan 27, 2025, at 3:29:08 PM** by the same account from the same IP address suggests further interaction with the system, potentially related to the RDP session. These events raise questions about the intent of these logons and their impact on system security.

Further investigation is required to assess whether these activities indicate malicious access or if additional security mechanisms may have been bypassed during the session.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "thscenariovm"
| where ActionType in ("LogonFailed", "LogonSuccess")  // Focus on logon attempts
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/593766f7-a106-4ab7-9c0e-ce0173d073d2">

---

### 2. Searched the `DeviceNetworkEvents` Table

Searched for processes and network activity originating from the device "thscenariovm" during and after the identified RDP session.

The dataset reveals multiple processes and network connections initiated shortly after the RDP session. On **Jan 27, 2025, at 3:43:43 PM**, a network connection was established with the internal IP address `10.0.0.5` using the process `svchost.exe`. This activity may indicate an attempt to interact with internal resources following the RDP session.

Additionally, on **Jan 27, 2025, at 3:44:28 PM**, a process `powershell_ise.exe` executed on the local machine, potentially indicating manual script execution or system reconnaissance. A connection to the loopback address `::1` on port `47001` was identified during this process, suggesting local inter-process communication or system modification.

Earlier activity on **Jan 27, 2025, at 2:49:26 PM**, initiated by `powershell.exe`, shows a connection to the external IP `20.10.127.193` over port `443`, which could represent an attempt to communicate with an external server.

These activities raise concerns about potential malicious intent, including data exfiltration, internal reconnaissance, or persistence mechanisms. Further investigation into the purpose and origin of these processes is recommended.

**Query used to locate event:**

```kql
DeviceNetworkEvents
| where DeviceName == "thscenariovm"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/e3f3394a-8095-47d2-8093-15988fc8666b">

---

### 3. Searched the `DeviceProcessEvents` Table

Searched for processes originating from the device "thscenariovm" during and after the identified RDP session.

The dataset reveals multiple processes initiated shortly after the RDP session. On Jan 27, 2025, at 3:48:54 PM, the process cmd.exe launched powershell.exe with the command: powershell.exe -ExecutionPolicy Bypass -File script.ps1 This activity indicates script execution, likely tied to actions performed during the session.

Additionally, on Jan 27, 2025, at 3:48:48 PM, powershell.exe executed the command: powershell -ExecutionPolicy Unrestricted -File another_script.ps1 This process corresponds to further scripted activity initiated post-logon, aligning with investigative steps.

Earlier activity on Jan 27, 2025, at 3:36:46 PM, initiated by cmd.exe, ran the command: powershell.exe -ExecutionPolicy Bypass -File download_payload.ps1 This action suggests file download or manipulation, consistent with the executed commands during the investigation.

These processes reflect actions taken as part of the investigation, including script execution and file manipulation. Further analysis may help confirm the full scope of changes initiated by these processes.
**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "thscenariovm"
| where InitiatingProcessFileName in ("cmd.exe", "powershell.exe")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/006dd09d-a56e-4bb3-b71e-382de5bb7ce6">

---

## **Chronological Event Timeline**

### 1. RDP Session Initiation
- **Time:** `3:29:12 PM, January 27, 2025`
- **Event:** The user `labuser` logged into the device `thscenariovm` via RDP.
- **Action:** Successful login detected.
- **Details:** Logon type `RemoteInteractive`, originating from IP address `10.0.8.5`.

### 2. Command Execution - PowerShell Script
- **Time:** `3:48:54 PM, January 27, 2025`
- **Event:** The user executed a PowerShell script using `cmd.exe`.
- **Action:** Process creation detected.
- **Command:** `powershell.exe -ExecutionPolicy Bypass -File script.ps1`

### 3. Network Activity - Internal Communication
- **Time:** `3:50:12 PM, January 27, 2025`
- **Event:** A PowerShell command initiated a connection to an internal IP address.
- **Action:** Network connection detected.
- **Details:** Connected to IP `10.0.0.5` using `powershell.exe`.

---

## Summary

The user `labuser` on the device `thscenariovm` accessed the system via RDP and executed actions that raised concerns. First, `labuser` successfully logged into the system from IP address `10.0.8.5` using Remote Desktop Protocol (RDP). Once logged in, they executed a PowerShell script via `cmd.exe` using a bypassed execution policy, indicating potential script-based activity.

Subsequently, the user initiated a PowerShell command to establish a network connection to an internal IP address (`10.0.0.5`). These actions reflect deliberate interaction with system resources and network communication, potentially indicating post-compromise behavior. The commands executed and the connections established are consistent with scripted activity during the session, raising the need for further investigation to ensure no unauthorized changes or persistence mechanisms were introduced.

---

## Response Taken

Unauthorized RDP access was confirmed on the endpoint `thscenariovm` by the user `labuser`. The device was isolated from the network, and the incident was escalated to the security team for further investigation. Additionally, the user's direct manager was notified to address potential policy violations.

---
