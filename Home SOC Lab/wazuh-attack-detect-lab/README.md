# Attack-and-Detect Home Lab with Wazuh

A VirtualBox lab where a Kali Linux attacker runs common attack techniques against Windows 11 and Ubuntu targets, and a Wazuh SIEM detects them. Each test records the command run, the Wazuh rule that fired, and the MITRE ATT&CK technique it maps to.

## Results at a glance

| # | Test | Target | Wazuh rule(s) | Level | MITRE ATT&CK | Detected |
|---|------|--------|---------------|-------|--------------|----------|
| 1 | SSH brute force | Ubuntu | 5710, 5503, 2502, 5712 | 5 to 10 | T1110 | Yes |
| 2 | RDP brute force | Windows 11 | 60122 | 5 | T1110, T1021.001 | Yes |
| 3 | Nmap SYN scan | Ubuntu | 100200, 100201 (custom) | 5 to 10 | T1046 | Yes (Ubuntu only) |
| 4 | Executable dropped in `Users\Public` | Windows 11 | 92207 | 12 | see `rule.mitre.id` in alert | Yes |
| 5 | Sysmon network connection (Event ID 3) | Windows 11 | 100110 (custom) | 3 | n/a (detection capability test) | Partial |

## Lab architecture

| VM | Role | Notes |
|----|------|-------|
| `kaliz` | Attacker | Kali Linux, Nmap, `sshpass`, `xfreerdp3` |
| `win11-victimNET` | Windows target | Windows 11 Enterprise Evaluation, Sysmon, Wazuh agent |
| `ubuntu-victim` | Linux target | Ubuntu 26.10, UFW with logging, Wazuh agent |
| `wazuh-server` | SIEM | Wazuh 4.14.9 (manager, indexer, dashboard) |

All VMs run on a VirtualBox **Bridged Adapter** on the same `192.168.0.0/24` network.

## Custom detection rules

Custom rules live in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh server.

| Rule ID | Level | Purpose |
|---------|-------|---------|
| 100100 | 3 | Sysmon process creation (Event ID 1) |
| 100110 | 3 | Sysmon network connection (Event ID 3) |
| 100200 | 5 | UFW firewall blocked a connection attempt |
| 100201 | 10 | Multiple UFW blocks from the same source (possible port scan) |

Rule 100110 as deployed:

```xml
<rule id="100110" level="3">
  <if_group>sysmon_event3</if_group>
  <description>sysmon network connection: $(win.eventdata.image) to $(win.eventdata.destinationIp):$(win.eventdata.destinationPort)</description>
</rule>
```

> Paste the XML for 100100, 100200 and 100201 from your `local_rules.xml` here.

The UFW rules depend on this block in the Ubuntu agent's `ossec.conf`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/ufw.log</location>
</localfile>
```

## Test 1: SSH brute force (Ubuntu)

**Action** (from Kali): repeated failed logins with a non-existent user.

```bash
for i in {1..6}; do sshpass -p 'wrongpass' ssh -o StrictHostKeyChecking=no baduser@<ubuntu-ip>; done
```

**Detection:** each attempt raised rules **5710** (non-existent user) and **5503** (PAM login failed), both level 5. Repeated failures escalated to **2502** (user missed the password more than one time) and **5712** (SSH brute force), both level 10.

**MITRE ATT&CK:** T1110, Brute Force.

![Test 1 evidence](screenshots/test1-ssh-bruteforce.png)

## Test 2: RDP brute force (Windows 11)

**Action** (from Kali):

```bash
for i in {1..5}; do xfreerdp3 /v:<windows-ip> /u:baduser /p:wrongpass /cert:ignore /auth-only; done
```

**Detection:** five alerts for rule **60122** (Logon Failure - Unknown user or bad password, level 5), generated from Windows Security Event ID 4625.

**MITRE ATT&CK:** T1110, Brute Force; T1021.001, Remote Desktop Protocol.

![Test 2 evidence](screenshots/test2-rdp-bruteforce.png)

## Test 3: Nmap SYN scan

**Action** (from Kali):

```bash
sudo nmap -Pn -sS -p- <target-ip>
```

**Detection (Ubuntu):** UFW logged the blocked probes. Custom rule **100200** (level 5) fired for each one, and **100201** (level 10, possible port scan) fired when many blocks came from one source. UFW's `low` logging level rate-limits entries, so Wazuh saw a sample of the probes, not every one.

**Detection (Windows):** none. See [Limitations](#limitations-and-lessons-learned).

**MITRE ATT&CK:** T1046, Network Service Discovery.

![Test 3 evidence](screenshots/test3-nmap-ubuntu.png)

## Test 4: Executable dropped in a public folder (Windows 11)

**Action** (on the Windows VM):

```powershell
New-Item -Path "C:\Users\Public\test_malware.exe" -ItemType File
```

**Detection:** Sysmon file-creation events were forwarded by the agent and matched rule **92207** (Executable file dropped in Users\Public folder, level 12). Repeated runs produced repeated alerts.

**MITRE ATT&CK:** use the technique shown in the `rule.mitre.id` field of the alert.

![Test 4 evidence](screenshots/test4-file-drop.png)

## Test 5: Sysmon network connection (Windows 11)

**Action** (on the Windows VM, repeated 8 times):

```powershell
Invoke-WebRequest http://example.com -UseBasicParsing | Out-Null
curl.exe -I https://example.com
```

**Detection:** Sysmon Event ID 3 reaches Wazuh and custom rule **100110** matches it. The alerts captured in the dashboard are from **OneDrive background connections**, not from the commands above. Event Viewer on the Windows VM showed Sysmon Event ID 3 entries for PowerShell, but no matching Wazuh alerts for the PowerShell or curl connections were found.

**MITRE ATT&CK:** not mapped. This test shows the detection pipeline works. It does not simulate an attack technique.

![Test 5 evidence](screenshots/test5-sysmon-network.png)

## Limitations and lessons learned

- **No Windows detection for the Nmap scan.** Windows Firewall logging was enabled (`pfirewall.log`) and the log was added to the agent as a `<localfile>`. The scan produced no `DROP TCP` entries, only unrelated UDP multicast noise (SSDP) from another device on the network. Without TCP drops in the log, there was nothing for a rule to match. A rule matching any `DROP` line would have caused false positives from that SSDP traffic, so I matched `DROP TCP` only.
- **PowerShell and curl connections were not alerted.** Sysmon logged them locally, but they did not appear in Wazuh. The cause was not established. Next steps: check for a `<query>` filter on the agent's Sysmon `localfile` block, and review the Sysmon config's `NetworkConnect` rules.
- **Misplaced `<localfile>` block stopped the agent.** The agent failed with error 1230 (invalid element) because a `<localfile>` had been placed inside `<client>`. It must sit directly under `<ossec_config>`. `xmllint --noout ossec.conf` finds this quickly.
- **A typo in `local_rules.xml` took the manager down.** A missing `>` on a rule tag made `wazuh-analysisd` fail on startup. Run `sudo /var/ossec/bin/wazuh-analysisd -t` before every manager restart.
- **Agent name case created a duplicate agent.** Re-enrolling as `win11-victimNET` after `win11-victimNet` created a second agent ID. Wazuh treats names as case-sensitive.
- **Kali needs `-Pn` against Windows.** Windows blocks ping by default, so Nmap can decide the host is down and skip the scan.
- **VM clock drift.** The VMs and the Wazuh server had different time settings, so timestamps differ across screenshots. Check `date` on every VM and the timezone before capturing evidence.

## Next steps

- Fix Windows scan visibility (firewall logging, or Sysmon network rules for inbound connections).
- Find out why PowerShell Event ID 3 events are not alerting.
- Add active response to block a source IP after the brute-force rules fire.
- Sync VM clocks with NTP and add a MITRE ATT&CK mapping table for every custom rule.

## Tools

VirtualBox, Kali Linux, Nmap, `sshpass`, FreeRDP (`xfreerdp3`), Sysmon, Wazuh 4.14.9, UFW.
