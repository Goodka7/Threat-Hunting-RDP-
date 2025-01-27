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

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.4.exe". 

At 3:30:55 PM on January 20, 2025, the user "labuser" created a process called "cmd.exe" on the device "hardmodevm." The process was located in C:\Windows\System32\cmd.exe, with the SHA256 hash of badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0. 

The command executed was:<span style="color: green;">
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command "Start-Process \"C:\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe\" -ArgumentList '/S' -NoNewWindow -Wait"</span>, which initiated the installation of the Tor Browser, silently.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName  == "hardmodevm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.4.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, Command = ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/a610791a-0559-410d-881d-397251039bbf">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser.The results showed user “labuser” accessed tor.exe (tor browser), firefox.exe(tor browser) several times:

At 3:42:33 PM to 3:42:26 PM (within the same minute), multiple instances of the "firefox.exe" process were created. These processes, all related to the Tor Browser, were executed from C:\Users\labuser\Desktop\Tor Browser\Browser\firefox.exe with various command parameters to handle different processes related to the browser's content processing, tab management, utility tasks, and GPU handling. Each "firefox.exe" instance had its own set of parameters, such as channels, preferences, and other configuration settings related to how the browser should run.
The SHA256 hash for all instances of "firefox.exe" is the same: 3034311292fade8a24ab8e7312cfb7132153c14b9383439b527e8296fe06a492.

At 3:42:49 PM on January 20, 2025, the user "labuser" created a process called "tor.exe" on the device "hardmodevm." The process was located at C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe, with the SHA256 hash c3b431779278278cda8d2bf5de5d4da38025717630bfeae1a82c927d0703cd28. 


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName  == "hardmodevm"
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, Command = ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/785257b9-5e7c-4ce6-8bb2-f9f0c8c59f0f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. The results showed user “labuser” did indeed use tor to connect to an url.

At 3:43:03 PM on January 20, 2025, a successful connection was made by the user "labuser" from the device "hardmodevm" to the remote IP address 45.21.116.144 on port 9001. The connection was made using the file "tor.exe," and the remote URL accessed was https://www.35yt53tip6fr4hoov4a.com.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName  == "hardmodevm"
| where InitiatingProcessAccountName == "labuser"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/f88b30e1-ccca-4a3a-b601-65992d08f1d3">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Time:** `3:29:50 PM, January 20, 2025`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe`

### 2. Process Execution - TOR Browser Installation

- **Time:** `3:30:55 PM, January 20, 2025`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-14.0.4.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command "Start-Process \"C:\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe\" -ArgumentList '/S' -NoNewWindow -Wait".`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Time:** `3:42:26 PM to 3:42:49 PM, January 20, 2025`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Time:** `3:43:03 PM, January 20, 2025`
- **Event:** A network connection to IP `45.21.116.144` on port `9001` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Time:** `3:43:36 PM, January 20, 2025` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Time:** `3:51 to 3:55 PM, January 20, 2025`
- **Event:** The user "labuser" created a folder named `tor-shopping-list` on the desktop, and created several files with names that are potentially related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list`

---

## Summary

The user "labuser" on the device "hardmodevm" installed and used the Tor Browser, taking actions that raised concerns. First, "labuser" silently initiated the installation of the Tor Browser through a PowerShell command. After the installation, they created the "tor.exe" file and executed it, which started the Tor service with specific configurations. Additionally, multiple instances of "firefox.exe" associated with the Tor Browser were launched, and the user successfully connected to the Tor network, accessing a remote IP and URL, suggesting the use of Tor for anonymous browsing. Furthermore, a folder (tor-shopping-list) containing several .txt and .json files was created, holding several files with names indicating potential illicit activity. These actions suggest that the user may have been engaging in suspicious or unauthorized activities using the Tor network.

---

## Response Taken

TOR usage was confirmed on the endpoint `hardmodevm` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
