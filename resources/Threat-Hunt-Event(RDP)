# Threat Event (Unauthorized RDP Access)
**Unauthorized Remote Desktop Protocol (RDP) Access**

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. **Reconnaissance**: The bad actor scans for open RDP ports (TCP 3389) on the target network.
   - Utilizes tools like Nmap or Shodan to find exposed RDP services.
2. **Brute Force or Exploit**: The bad actor attempts to authenticate using brute force or exploits a vulnerability (e.g., BlueKeep).
   - Common usernames attempted: `Administrator`, `Admin`, `root`, etc.
   - Common passwords: `Password123!`, `P@ssw0rd!`, etc.
3. **Successful Login**: The attacker successfully logs into the machine over RDP.
   - Logs show the source IP address used for RDP access.
4. **Command Execution**: The attacker executes commands or malicious scripts once logged in (e.g., downloading malware, lateral movement).
5. **Clean-Up**: The attacker may remove logs to cover their tracks or create backdoors for persistent access (e.g., creating new user accounts or disabling security software).

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceLogonEvents                                                            |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table |
| **Purpose**| Used to detect successful RDP logins, including login source IP and username. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents                                                           |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| **Purpose**| Used to detect network activity over port 3389 and connections from suspicious IP addresses. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents                                                           |
| **Info**| https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose**| Used to detect RDP session creation or any commands executed remotely. |

---

## Related Queries:
```kql
// Detecting RDP login attempts
DeviceLogonEvents
| where LogonType == 10 // RDP login
| project Timestamp, DeviceName, AccountName, SourceIP, ActionType

// Failed login attempts (brute force) for RDP
DeviceLogonEvents
| where LogonType == 10
| where ActionType == "LogonFailure"
| project Timestamp, DeviceName, AccountName, SourceIP, ActionType

// Detect RDP traffic on port 3389 from suspicious IPs
DeviceNetworkEvents
| where RemotePort == 3389
| where RemoteIP in ('suspicious_ip_range')
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName

// Detect suspicious processes spawned after RDP login
DeviceProcessEvents
| where ProcessCommandLine contains "cmd.exe" or "powershell.exe"
| where InitiatingProcessFileName == "mstsc.exe" // mstsc.exe is the RDP client
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```
---

## Created By:
- **Author Name**: James Harrington
- **Author Contact**: https://www.linkedin.com/in/Goodk47/
- **Date**: January 24, 2024

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `January 24, 2024`  | `James Harrington`   
