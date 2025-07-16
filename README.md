<kbd>
<img width="400" src="https://github.com/user-attachments/assets/530ce00f-0c4a-4f20-b365-05f3a697bbec" alt="Tor Logo with the onion and a crosshair on it"/>
</kbd>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/JustinSoflin/Threat-Hunting-Scenario-Tor-Browser-Usage-/blob/main/threat-hunting-scenario-tor-event-creation.md)
## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that an employee may be using TOR browser to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file containing “tor” for user “labproject’. Discovered what seems to be a tor browser download with some tor-related files created afterwards, the most notable of which is a file on the user’s desktop named ‘tor-shopping-list’, created at 2025-05-06T20:54:23.3987908Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "justins-tor-bro"
| where InitiatingProcessAccountName == "labproject"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-05-06T20:28:09.1850296Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<kbd>
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/8162b636-af53-47d9-b2d0-910f24af336a">
</kbd>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched DeviceProcessEvents table for any ProcessCommandLine that contains the string “ tor-browser-windows”. Logs show a silent installation of the Tor Browser (version 14.5.1) was initiated by the user account labproject on the system justins-tor-bro at 2025-05-06T20:44:08.3760807Z. The executable was run from the user's Downloads folder and appears to have been installed without user prompts (/S switch)

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "justins-tor-bro"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256
```
<kbd>
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/895917c3-4a24-455f-acca-5e4b5c341d1f">
</kbd>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication of user “labproject” opening the tor browser; logs confirm tor browser was launched at: 2025-05-06T20:45:06.0206654Z
There were also other instances of firefox.exe (tor) and tor.exe that spawned afterwards. <br>
Seeing -contentproc with -isForBrowser and tab means a web page (tab) was opened in Firefox. This does confirm browser use, beyond just launching the main process.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "justins-tor-bro"
| where FileName has_any ("tor.exe", "firefox.exe", "browser")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256
```
<kbd>
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/5d5d411d-414b-4f48-a467-f8ae770bbc9a">
</kbd>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched DeviceNetworkEvents table for any indication that the tor browser established any connections. On 2025-05-06T20:45:35.0448696Z, the device named "justins-tor-bro" (logged in as labproject) successfully established a network connection using tor.exe located at C:\Users\labproject\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe. The connection was made to the remote IP addresses 158.101.203.38 and 94.23.121.150, both via port 9001, which is commonly associated with the Tor network.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "justins-tor-bro"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9050", "9051", "5000", "9052", "9100", "9030", "9150", "9151")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<kbd>
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/9c35b097-58a7-433d-85ee-64c46ecfec07">
</kbd>

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** 2025-05-06T20:28:09.1850296Z
- **Event:** Initial file activity related to Tor detected.
- **Device** justins-tor-bro
- **User Account** labproject
- **File Indicator** Files containing the string "tor"

### 2. Silent Installation of Tor Browser

- **Timestamp:** 2025-05-06T20:44:08.3760807Z  
- **Event:** Silent installation of Tor Browser version 14.5.1  
- **Folder Path:** C:\Users\labproject\Downloads  
- **Command Line:** tor-browser-windows-x86_64-portable-14.5.1.exe  /S  

### 3. Launch of Tor Browser

- **Timestamp:** 2025-05-06T20:45:06.0206654Z  
- **Event:** Launch of Tor Browser (tor.exe and firefox.exe processes observed)  
- **Folder Path:**  
  - C:\Users\labproject\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe  
  - C:\Users\labproject\Desktop\Tor Browser\Browser\firefox.exe  

### 4. Outbound Tor Network Connection

- **Timestamp:** 2025-05-06T20:45:35.0448696Z  
- **Event:** Outbound connection via Tor network established  
- **Remote IP:** 158.101.203.38  
- **Remote Port:** 9001  
- **Process Name:** tor.exe  
- **Folder Path:** C:\Users\labproject\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe  

### 5. Suspicious File Creation

- **Timestamp:** 2025-05-06T20:54:23.3987908Z  
- **Event:** File tor-shopping-list created  
- **Folder Path:** C:\Users\labproject\Desktop  
- **File Name:** tor-shopping-list.txt

---

## Summary

On May 6, 2025, the user account labproject on device justins-tor-bro initiated the silent installation of the Tor Browser (v14.5.1), followed by its successful launch. Shortly after, the browser established an outbound network connection to IP 158.101.203.38 over port 9001, which is a known Tor relay port, confirming that Tor network usage occurred. Approximately 9 minutes later, a file named tor-shopping-list was created on the user’s desktop, suggesting intent to engage in transactions through the Tor network. The sequence of these events indicates deliberate and covert usage of the Tor browser within the corporate environment.

---

## Response Taken

TOR usage was confirmed on endpoint justins-tor-bro by the user labproject. The device was isolated and the user's direct manager was notified.

---
