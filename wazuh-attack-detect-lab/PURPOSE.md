# Purpose of Each Test

This lab checks whether a Wazuh SIEM can see an attack at each stage, from reconnaissance to command-and-control. Each test below simulates one stage, states what it proves, and records the outcome. The results table and evidence are in the [README](README.md).

## How the tests fit together

```
Recon (Test 3) -> Initial access (Tests 1 and 2) -> Post-compromise (Test 4) -> Command and control (Test 5)
```

Together they show where detection works and where visibility gaps remain.

---

## Test 1: SSH brute force (Ubuntu)

**Attack stage:** Initial access. **MITRE ATT&CK:** T1110 (Brute Force)

**Purpose:** Attackers guess passwords against exposed login services to gain access. This test checks that Wazuh collects Linux authentication logs and that repeated failures are correlated into a higher-severity "brute force" alert, not only logged as isolated events.

**What success looks like:** Single failed logins alert at level 5, then escalate to level 10 when many failures arrive in a short window.

**Outcome:** Detected (rules 5710, 5503, 2502, 5712).

---

## Test 2: RDP brute force (Windows 11)

**Attack stage:** Initial access. **MITRE ATT&CK:** T1110 (Brute Force), T1021.001 (Remote Desktop Protocol)

**Purpose:** Remote Desktop is one of the most attacked services on the internet. This test checks that Windows Security events (Event ID 4625, failed logon) are collected by the agent and turned into alerts, which shows detection works on Windows as well as Linux.

**What success looks like:** Each failed RDP logon from the attacker appears as a Wazuh alert.

**Outcome:** Detected (rule 60122). A higher-level correlation alert did not fire with five attempts, since that needs more failures in a short window.

---

## Test 3: Nmap SYN scan

**Attack stage:** Reconnaissance. **MITRE ATT&CK:** T1046 (Network Service Discovery)

**Purpose:** Before attacking, an attacker maps open ports and services. This test checks whether a port scan is visible. On Ubuntu, UFW logs the blocked probes and custom rules 100200 and 100201 turn a flood of blocks into one "possible port scan" alert.

**What success looks like:** Individual blocked connections alert at level 5, and a burst from one source alerts at level 10.

**Outcome:** Detected on Ubuntu. Not detected on Windows, because Windows Firewall did not log TCP drops for the scan. This gap is documented in the README as a limitation.

---

## Test 4: Executable dropped in a public folder (Windows 11)

**Attack stage:** Post-compromise (staging tools). **MITRE ATT&CK:** see `rule.mitre.id` in the alert

**Purpose:** After getting in, attackers often write malware or tools to world-writable folders such as `C:\Users\Public`. This test checks that Sysmon file-creation events reach Wazuh and that an executable appearing in a suspicious location is flagged at high severity.

**What success looks like:** A high-severity alert naming the dropped file and the folder.

**Outcome:** Detected (rule 92207, level 12).

---

## Test 5: Sysmon network connection (Windows 11)

**Attack stage:** Command and control (endpoint telemetry). **MITRE ATT&CK:** not mapped, since this is a capability test and not an attack technique

**Purpose:** Malware often connects out to a server it controls. This test checks that Sysmon network-connection events (Event ID 3) are collected and matched by custom rule 100110, so you can see which process connected where.

**What success looks like:** An alert showing the process image, destination IP and port.

**Outcome:** Partial. Rule 100110 fires, but the alerts captured are from OneDrive background traffic. The `Invoke-WebRequest` and `curl.exe` connections produced local Sysmon events but no matching Wazuh alerts, and the cause was not established.

---

## What the lab demonstrates

- Wazuh detects authentication attacks on both Windows and Linux.
- Custom rules can turn raw firewall logs into scan detection (Ubuntu).
- Endpoint telemetry from Sysmon is useful but needs careful configuration, and some gaps were found (Windows scan visibility, PowerShell network events).
- Documenting failures honestly shows where detection coverage needs work, which is the point of testing a detection pipeline.
