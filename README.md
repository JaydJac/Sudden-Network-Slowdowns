# Sudden-Network-Slowdowns



## 1️⃣ Preparation
### 🎯 Goal: Set up the hunt by defining what you're looking for.
The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the `10.0.0.0/16` network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

### 🕵️ Activity: Develop a hypothesis based on threat intelligence and security gaps.
- All traffic originating from within the local network is by default allowed by all hosts.
- There is unrestricted use of PowerShell and other applications in the environment.
- It’s possible someone is either downloading large files or performing port scanning within the local network.

## 2️⃣ Data Collection
### 🎯 Goal: Gather relevant data from logs, network traffic, and endpoints.
- Consider inspecting the logs for excessive successful/failed connections from any devices.
- If discovered, pivot and inspect those devices for any suspicious file or process events.

### 📊 Activity: Ensure data is available from all key sources for analysis.
Ensure the relevant tables contain recent logs:
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceProcessEvents`

#### 🔍 Findings:
‘Jayda-mde-0327’ and ‘windows-target-1’ were found failing several connection requests against itself and another host on the same network:
```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

![image](https://github.com/user-attachments/assets/784aaaf5-46f7-4842-b873-dea44c778cee)


## 3️⃣ Data Analysis
### 🎯 Goal: Analyze data to test your hypothesis.

### 📊 Activity: Look for anomalies, patterns, or indicators of compromise (IOCs).
- Look for excessive network connections to/from any hosts.
- Take note of the query/logs/time.

#### 🔍 Findings:
- Observed failed connection request from a suspected host (`10.0.0.5`), indicating a possible port scan due to the sequential order of ports being accessed.
```kusto
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

## 4️⃣ Investigation
### 🎯 Goal: Investigate any suspicious findings.

### 🔍 Activity: Dig deeper into detected threats, determine their scope, and escalate if necessary.
- Search `DeviceFileEvents` and `DeviceProcessEvents` tables around the same time based on findings from `DeviceNetworkEvents`.

#### 🔍 Findings:
- A PowerShell script named `portscan.ps1` was launched at `2025-03-31T00:38:02.9918814Z`.
```kusto
let VMName = "windows-target-1";
let specificTime = datetime(2025-03-31T00:38:02.9918814Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

![image](https://github.com/user-attachments/assets/7164b37c-403a-441b-a07d-62b25e2be31c)


- The port scan was launched by the SYSTEM account—unexpected behavior not pre-scheduled by admins.

## 5️⃣ Response
### 🎯 Goal: Mitigate any confirmed threats.

### 🔧 Activity: Work with security teams to contain, remove, and recover from the threat.
- Isolated the VM and conducted a malware scan.
- The malware scan produced no results.
- Kept the device isolated and submitted a ticket for reimaging/rebuilding.

## 6️⃣ Documentation
### 🎯 Goal: Record your findings and learn from them.

### 📑 Activity: Document findings to improve future hunts and defenses.
- Detailed logs and queries saved for reference.
- Findings shared with the security team for awareness.

## 7️⃣ Improvement
### 🎯 Goal: Improve security posture or refine methods for the next hunt.

### 📈 Activity: Adjust strategies and tools based on what worked or didn’t.
- Implemented stricter PowerShell execution policies.
- Enhanced network segmentation to limit unrestricted internal traffic.
- Enforced least privilege principles for SYSTEM account operations.

## 🔥 MITRE ATT&CK Framework Related TTPs:
- `T1046` – Network Service Discovery
- `T1018` – Remote System Discovery
- `T1059.001` – Command and Scripting Interpreter: PowerShell
- `T1078` – Valid Accounts
- `T1548.002` – Abuse Elevation Control Mechanism: Bypass User Access Control
- `T1562.001` – Impair Defenses: Disable or Modify Tools
- `T1070.004` – Indicator Removal: File Deletion
- `T1021.001` – Remote Services: Remote Desktop Protocol (RDP)
- `T1041` – Exfiltration Over C2 Channel

## ✅ Response Actions:
- 🔐 **Hardened firewall rules** to block unnecessary traffic.
- 🚫 **Restricted PowerShell execution** on non-administrative accounts.
- 🔄 **Implemented account lockout policies** to prevent brute-force attempts.
- 🔑 **Enabled MFA** for critical system accounts.

---
### 📝 **Summary:**
Though the device was exposed to the internet and clear brute-force attempts were detected, **no evidence of unauthorized access was found.** The investigation confirmed attempted attacks but no successful breaches. The environment has been hardened to prevent future occurrences. 🚀


### 🎯 Conclusion
Though the device was exposed to the internet and clear brute-force attempts took place, **no unauthorized access or brute-force success was detected**. Further mitigation steps were implemented to improve security posture and prevent future incidents.

---
