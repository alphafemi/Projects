# Home SOC Lab: Attack and Detect with Wazuh

A virtual lab where I attack two victim machines from Kali Linux and detect those attacks in a Wazuh SIEM. I wrote custom decoders and rules for detections that Wazuh does not provide out of the box.

**Skills shown:** SIEM deployment, agent configuration, log analysis, custom decoder and rule writing, Sysmon tuning, MITRE ATT&CK mapping, troubleshooting.

---

## Lab Architecture

| VM | Hostname / Agent name | IP | Role | OS |
| --- | --- | --- | --- | --- |
| Attacker | `kaliz` | 192.168.0.159 | Generates attack traffic | Kali Linux |
| Victim (Linux) | `ub11` / `ubuntu-victim` | 192.168.0.171 | Monitored endpoint | Ubuntu 26.10 |
| Victim (Windows) | `wn11` / `win11-victimNet` | 192.168.0.109 | Monitored endpoint | Windows 11 Enterprise (evaluation) |
| SIEM | `wazuh-server` | 192.168.0.162 | Collects, decodes, alerts | Wazuh v4.14.9 OVA |

- **Hypervisor:** VirtualBox, all VMs on bridged networking so they share one LAN.
- **Telemetry:** Wazuh agent on both victims. Sysmon v15.22 (SwiftOnSecurity config) on Windows. UFW firewall logging on Ubuntu.

```
                 +--------------------+
                 |   Wazuh server     |
                 |  192.168.0.162     |
                 +---------^----------+
                           | agent logs (1514/tcp)
          +----------------+----------------+
          |                                 |
+---------+----------+            +---------+----------+
|  ubuntu-victim     |            |  win11-victimNet   |
|  192.168.0.171     |            |  192.168.0.109     |
|  UFW + auth logs   |            |  Sysmon + Security |
+---------^----------+            +---------^----------+
          |                                 |
          +----------------+----------------+
                           | attacks
                 +---------+----------+
                 |  Kali (kaliz)      |
                 |  192.168.0.159     |
                 +--------------------+
```

---

## Setup Summary

1. Imported the Wazuh OVA into VirtualBox and confirmed the dashboard at `https://192.168.0.162`.
2. Built the Ubuntu VM, installed the Wazuh agent, enabled `ufw` with logging.
3. Built the Windows 11 VM (64 GB disk, EFI, manual install), installed the Wazuh agent and Sysmon.
4. Built Kali and confirmed it could reach both victims.
5. Confirmed both agents showed **Active** in the dashboard before testing.

---

## Custom Detection Content

Wazuh has no default rule for UFW firewall blocks, and its default rule for Sysmon network connections (Event ID 3) does not store an alert. Those events were received but never shown, so I wrote the following.

### Agent config (Ubuntu): `/var/ossec/etc/ossec.conf`

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/ufw.log</location>
</localfile>
```

### Decoder (Wazuh server): `/var/ossec/etc/decoders/local_decoder.xml`

```xml
<decoder name="ufw-block">
  <parent>kernel</parent>
  <prematch type="pcre2">\[UFW BLOCK\]</prematch>
  <regex type="pcre2">SRC=(\S+) DST=(\S+).*PROTO=(\S+) SPT=(\d+) DPT=(\d+)</regex>
  <order>srcip, dstip, protocol, srcport, dstport</order>
</decoder>
```

### Rules (Wazuh server): `/var/ossec/etc/rules/local_rules.xml`

```xml
<group name="sysmon,">
  <rule id="100100" level="3">
    <if_sid>61603</if_sid>
    <description>Sysmon process created: $(win.eventdata.image)</description>
  </rule>

  <rule id="100110" level="3">
    <if_group>sysmon_event3</if_group>
    <description>Sysmon network connection: $(win.eventdata.image) to $(win.eventdata.destinationIp):$(win.eventdata.destinationPort)</description>
  </rule>
</group>

<group name="firewall,ufw,">
  <rule id="100200" level="5">
    <decoded_as>kernel</decoded_as>
    <match>UFW BLOCK</match>
    <description>UFW firewall blocked a connection attempt</description>
    <group>firewall_drop,</group>
  </rule>

  <rule id="100201" level="10" frequency="8" timeframe="60">
    <if_matched_sid>100200</if_matched_sid>
    <same_source_ip />
    <description>Multiple UFW blocks from the same source - possible port scan</description>
    <group>recon,</group>
  </rule>
</group>
```

Rule 100201 correlates 8 or more blocked connections from the same source within 60 seconds into one higher-severity alert.

I checked the decoder and rules with `wazuh-logtest` before restarting the manager. A passing run showed rule `100200` at level 5 with "Alert to be generated".

---

## Tests and Results

Each test was run one at a time, and the matching alert was confirmed in the Wazuh dashboard (Threat Hunting > Events) before moving on.

| # | Attack | Target | Command / action | Wazuh detection | Level | MITRE ATT&CK |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | SSH brute force | `ubuntu-victim` | Repeated failed `ssh` logins from Kali | Rules 5710, 5503, 5712, 2502 | 5 to 10 | T1110 Brute Force |
| 2 | RDP brute force | `win11-victimNet` | Repeated failed `xfreerdp` logins from Kali | Rule 60122, then "Multiple Windows Logon Failures" | 5 to 10 | T1110 Brute Force |
| 3 | Port scan | `ubuntu-victim` | `nmap -sS -p- 192.168.0.171` | Custom rules 100200 and 100201 | 5 to 10 | T1046 Network Service Discovery |
| 4 | Suspicious file drop | `win11-victimNet` | Copied an `.exe` into `C:\Users\Public` | Rule 92207, "Executable file dropped in Users\\Public folder" | 12 | T1036 Masquerading (staging behavior) |
| 5 | Network connection logging | `win11-victimNet` | `Invoke-WebRequest http://example.com` | Custom rule 100110 | 3 | Visibility for T1071 |

**Pattern across tests 1 to 3:** individual failures raise level 5 alerts, and a correlation rule escalates repeated activity to level 10. The same detection logic works on both Windows and Linux.

### Test 1: SSH brute force (Ubuntu)

Failed logins from Kali with non-existent users and bad passwords.

- `sshd: Attempt to login using a non-existent user` (rule 5710, level 5), fired repeatedly
- `PAM: User login failed` (rule 5503, level 5)
- `syslog: User missed the password more than one time` (rule 2502, **level 10**), the escalation

![SSH brute force alerts](docs/test1-ssh.png)

### Test 2: RDP brute force (Windows)

Repeated failed RDP logins from Kali with `xfreerdp`.

- `Logon Failure - Unknown user or bad password` (level 5), one per attempt, from Windows Security Event ID 4625
- `Multiple Windows Logon Failures` (**level 10**), the correlated alert, fired twice

![RDP brute force alerts](docs/test2-rdp.png)

### Test 3: Nmap port scan (Ubuntu), custom rules

`nmap -sS -p- 192.168.0.171` from Kali. UFW logged each blocked SYN packet, and my decoder and rules turned those into alerts.

- 45 events in 15 minutes
- `UFW firewall blocked a connection attempt` (rule 100200, level 5), one per blocked packet
- `Multiple UFW blocks from the same source - possible port scan` (rule 100201, **level 10**), fired as the scan started

![Nmap scan alerts](docs/test3-nmap.png)

### Test 4: Suspicious file drop (Windows)

Copied a harmless Windows executable into `C:\Users\Public` under a different name, which imitates malware staging. Sysmon file-creation events (Event ID 11) fed the detection.

- `Executable file dropped in Users\Public folder` (rule 92207, **level 12**)
- 15 events in the window, one per run of the command

![File drop alerts](docs/test4-filedrop.png)

### Test 5: Sysmon network connections (Windows), custom rule

Sysmon logged Event ID 3 locally, but nothing reached the dashboard until I added rule 100110. The six alerts below came from Windows Defender and OneDrive background traffic, which shows the rule works for any process.

![Sysmon network connection alerts](docs/test5-sysmon.jpg)

---

## Additional Detections Seen in an Earlier Build

During the first build of the lab (before I rebuilt it cleanly), Wazuh also raised these on `win11-victimNET`:

| Rule | Description | Level |
| --- | --- | --- |
| 92213 | Executable file dropped in folder commonly used by malware | 15 |
| 92307 | Evidence of new service creation found in registry | 3 |
| 92031 | Discovery activity executed | 3 |
| 19005 and others | CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 results | 3 to 9 |

---

## Problems I Solved

| Problem | Cause | Fix |
| --- | --- | --- |
| Windows 11 install failed in VirtualBox ("could not complete the installation") | Unattended install and VM settings | Manual install, 64 GB disk, EFI enabled |
| UFW logs written locally but nothing in Wazuh | `/var/log/ufw.log` was not being collected | Added the `<localfile>` block to the **agent's** `ossec.conf` |
| Config edit had no effect | Edited the Wazuh **server's** `ossec.conf` instead of the agent's | Agent settings go on the agent. Decoders and rules go on the server. |
| Events still missing after forwarding was fixed | Wazuh only stores events that match a rule (`logall` is `no`) | Wrote a custom decoder and rules |
| `Syntax error on regex` in logtest | Default regex engine rejects `\[` | Switched the decoder to `type="pcre2"` |
| Custom decoder never matched | Built-in `kernel` decoder claims the line first | Made `ufw-block` a child of `kernel` |
| `Attribute has no value` XML error | Missing `>` on a `<rule>` line | Validated with `wazuh-logtest` |
| `Invalid ip address: 'UFW BLOCK'` | Leftover example rule using `<srcip>` | Removed the old rule block |
| Sysmon Event ID 3 not visible | SwiftOnSecurity config filters most network connections, and the default rule does not store an alert | Temporarily logged all connections, wrote rule 100110, then restored the filtered config |

---

## Limitations

- **No port-scan detection on Windows.** I enabled Windows Firewall logging (`pfirewall.log`) and added it to the agent config, but the Nmap scan produced no `DROP TCP` lines, so there was nothing to detect. A scan that Windows does not log is a visibility gap, and the likely next step is Suricata or a Windows firewall profile that blocks and logs.
- **Lab only.** The rule thresholds (8 blocks in 60 seconds) are tuned to my scans, not to production traffic.
- **Unfiltered Sysmon logging** was used temporarily for testing and is too noisy for real use.

---

## Key Takeaways

- A SIEM is only as good as its log sources and rules. Getting data in is half the work.
- `wazuh-logtest` finds decoder and rule errors before a restart.
- Verify each layer on its own (does the log exist locally, does the agent forward it, does a rule match) instead of guessing.
- Tune noisy telemetry. Logging everything is useful for testing and bad for analysts.

---

## Next Steps

- Add active response to block repeated offenders.
- Add Suricata for network-level detection, including scans of the Windows host.
- Map more detections to MITRE ATT&CK and build a dashboard.

---

*Built as a hands-on project after completing TryHackMe SOC Level 1.*