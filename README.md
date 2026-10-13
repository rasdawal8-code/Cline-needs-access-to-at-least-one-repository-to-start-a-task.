# SOC Triage Toolkit

**Educational browser-based SOC triage toolkit for network traffic and Windows security event log analysis.**

All analysis happens entirely inside your browser. No data is uploaded, transmitted, or stored anywhere.

---

## Table of Contents

1. [What This Toolkit Is](#what-this-toolkit-is)
2. [Project Purpose](#project-purpose)
3. [How to Run Locally on Windows](#how-to-run-locally-on-windows)
4. [How to Use Each Tool](#how-to-use-each-tool)
5. [How to Export a Wireshark CSV](#how-to-export-a-wireshark-csv)
6. [How to Export Windows Security Events as CSV](#how-to-export-windows-security-events-as-csv)
7. [Supported CSV Fields — Network Tool](#supported-csv-fields--network-tool)
8. [Supported CSV Fields — Windows Tool](#supported-csv-fields--windows-tool)
9. [Supported Windows Event IDs](#supported-windows-event-ids)
10. [Network Detection Rules](#network-detection-rules)
11. [Windows Detection and Correlation Rules](#windows-detection-and-correlation-rules)
12. [Default Thresholds](#default-thresholds)
13. [Why Thresholds Are Not Universal](#why-thresholds-are-not-universal)
14. [Sample Data](#sample-data)
15. [Privacy Design](#privacy-design)
16. [Security Considerations](#security-considerations)
17. [Accessibility](#accessibility)
18. [Limitations](#limitations)
19. [False Positives](#false-positives)
20. [Educational Use](#educational-use)
21. [Future Improvements](#future-improvements)
22. [Video Demonstration Guide](#video-demonstration-guide)

---

## What This Toolkit Is

The SOC Triage Toolkit is a static web application with two independent modules:

- **Network Traffic Triage Tool** — analyses Wireshark CSV packet exports
- **Windows Security Event Log Triage Tool** — analyses Windows Event Viewer CSV exports

Both tools are designed to teach cybersecurity students how Security Operations Centre (SOC) analysts investigate unusual activity, correlate events, and decide what deserves further investigation.

The central lesson of the entire toolkit:

> **Detection tells an analyst where to look. Investigation determines what actually happened.**
>
> An anomaly is a starting point for investigation, not proof of compromise.

---

## Project Purpose

This toolkit is educational. It is intended to help cybersecurity students understand:

- How network traffic patterns are investigated
- How Windows security events work
- How SOC analysts correlate events across time
- How false positives occur and why they matter
- How analysts decide what deserves further investigation
- Why a single alert rarely tells the complete story

The toolkit does **not** claim to be a production security product. It is a teaching aid.

---

## How to Run Locally on Windows

**Nothing needs to be installed.**

1. Download or unzip the project folder to your computer (e.g. your Desktop)
2. Open the folder
3. Double-click `index.html`
4. It will open in your default browser (Chrome, Edge, or Firefox recommended)
5. Choose a tool from the landing page
6. Use the **Load Sample** buttons to explore without needing real data

To use your own data, export a CSV from Wireshark or Windows Event Viewer and upload it using the file upload area.

**Note:** If you load sample files and see a browser error about file access, try opening the file using a local web server. The easiest way is:
- In VS Code: use the **Live Server** extension
- Or run: `python -m http.server 8080` in the project folder and open `http://localhost:8080`

The built-in fallback samples are embedded directly in the JavaScript, so the tools work even without a server.

---

## How to Use Each Tool

### Network Traffic Triage Tool

1. Open `network.html` (or click **Network** from the landing page)
2. Use **Load Sample** buttons to try the built-in scenarios, or upload your own Wireshark CSV
3. Review the **Overview** tab for summary statistics, protocol distribution, and top hosts
4. Check the **Findings & Alerts** tab for detection rule results
5. Click any finding to expand the full explanation
6. Use the **Top Hosts** tab to review source and destination activity
7. Adjust thresholds in the **Thresholds** tab and click **Re-analyse**
8. Read the **How to Analyse** tab for analyst guidance

### Windows Event Log Triage Tool

1. Open `windows.html` (or click **Windows** from the landing page)
2. Use **Load Sample** buttons to try the built-in scenarios, or upload your own event CSV
3. Review the **Overview** tab for event counts, Event ID distribution, and timeline
4. Check the **Findings & Alerts** tab for correlated findings
5. Click any finding to expand the full explanation
6. Review the **Accounts** tab for authentication summaries
7. Adjust thresholds in the **Thresholds** tab
8. Read the **Event ID Reference** and **How to Analyse** tabs for analyst guidance

---

## How to Export a Wireshark CSV

1. Open Wireshark
2. Start a capture on an authorised network interface
3. Stop the capture when you have enough data
4. Go to: **File → Export Packet Dissections → As CSV…**
5. In the dialog, select **All packets**
6. Ensure the displayed columns include: No., Time, Source, Destination, Protocol, Length, Info
7. Save the file with a `.csv` extension
8. Upload into the Network Triage Tool

> **Important:** Only capture traffic on networks and systems you own or have explicit written authorisation to monitor. Capturing network traffic without authorisation may be illegal.

---

## How to Export Windows Security Events as CSV

**Method 1 — Event Viewer GUI:**
1. Open **Windows Event Viewer** (search in Start menu)
2. Navigate to **Windows Logs → Security**
3. Optionally filter by Event ID or time range using **Filter Current Log**
4. Go to **Action → Save All Events As…**
5. Choose **CSV (Comma Separated)** as the file format
6. Save and upload into the Windows Event Log Triage Tool

**Method 2 — PowerShell (more complete):**
```powershell
Get-WinEvent -LogName Security -MaxEvents 1000 | Select-Object Id,LevelDisplayName,TimeCreated,ProviderName,TaskDisplayName,Message | Export-Csv -Path .\security-events.csv -NoTypeInformation
```

For specific Event IDs:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4624,4720,4732,1102} | Select-Object Id,LevelDisplayName,TimeCreated,ProviderName,TaskDisplayName,Message | Export-Csv -Path .\filtered-events.csv -NoTypeInformation
```

> **Note:** The CSV column names from Event Viewer and PowerShell differ. The tool handles both formats automatically.

---

## Supported CSV Fields — Network Tool

The tool automatically detects column names and handles variations.

| Field | Accepted column names |
|-------|----------------------|
| Packet number | No., Num, Number |
| Timestamp | Time, Timestamp, DateTime |
| Source IP | Source, src, ip.src, SourceIP |
| Destination IP | Destination, dst, dest, ip.dst |
| Protocol | Protocol, Proto, Type |
| Packet length | Length, Len, Size, Bytes |
| Info/description | Info, Description, Detail, Summary |

If Source or Destination columns cannot be found, the tool displays a clear error message.

---

## Supported CSV Fields — Windows Tool

| Field | Accepted column names |
|-------|----------------------|
| Event ID | Event ID, EventID, Id |
| Severity | Level, LevelDisplayName, Type |
| Timestamp | Date and Time, TimeCreated, DateTime |
| Source/Provider | Source, SourceName, Provider |
| Task/Category | Task Category, Task, TaskDisplayName |
| User/Account | User, Username, Account |
| Computer | Computer, ComputerName, Machine |
| Message | Message, Description, Details |

---

## Supported Windows Event IDs

| Event ID | Name | Default Severity |
|----------|------|------------------|
| 4624 | Successful Logon | Informational |
| 4625 | Failed Logon | Low (escalates with volume) |
| 4720 | User Account Created | Medium |
| 4726 | User Account Deleted | Low |
| 4728 | Member Added to Global Security Group | Medium |
| 4732 | Member Added to Local Security Group | Medium |
| 4688 | Process Created | Informational |
| 4104 | PowerShell Script Block Logged | Low (High if obfuscated) |
| 7045 | Service Installed | Medium |
| 1102 | Security Audit Log Cleared | High |

---

## Network Detection Rules

### Rule 1 — High Packet Volume
Triggers when one source IP sends more packets than the configured threshold.  
Default: **more than 50 packets**  
Possible causes: file transfers, backups, software updates, scanning, automated tools, malicious activity.

### Rule 2 — Possible Host Scanning
Triggers when one source communicates with an unusually large number of unique destination addresses.  
Default: **more than 10 unique destinations**  
Possible causes: network management tools, scanning, distributed applications, misconfiguration.

### Rule 3 — Possible Port Scanning
Triggers when one source contacts many different ports on the same destination host.  
Detected from the Info field where available.  
Default: **more than 10 unique destination ports**  
Possible causes: service discovery, port scanning, complex application behaviour.

### Rule 4 — High ICMP Activity
Triggers when one source generates an elevated number of ICMP packets.  
Default: **more than 30 ICMP packets**  
Possible causes: ping sweeps, network monitoring, troubleshooting, denial-of-service activity.

### Rule 5 — High DNS Query Activity
Triggers when one source generates an elevated number of DNS packets.  
Default: **more than 30 DNS packets**  
Possible causes: normal browsing, automated tools, misconfiguration, beaconing.

### Rule 6 — Repeated Source-to-Destination Communication
Triggers when one source sends a high number of packets to the same destination.  
Default: **more than 40 packets between the same pair**  
Possible causes: normal application traffic, persistent connections, beaconing, data exfiltration.

---

## Windows Detection and Correlation Rules

### Rule 1 — Repeated Failed Logons
Triggers when the same account has multiple Event ID 4625 events.  
Default: **5 or more failures for the same account**

### Rule 2 — Failed Logons Followed by Success
Triggers when repeated 4625 failures are followed by a 4624 success for the same account.  
Severity: **High**  
This correlation is one of the most important findings in the Windows tool.

### Rule 3 — Account Created Then Privilege Added
Triggers when Event 4720 (account created) is followed by 4728 or 4732 (group membership) for the same account name.  
Severity: **High**

### Rule 4 — Security Audit Log Cleared (1102)
Always generates a **High** severity alert.  
Even a single occurrence should be investigated.

### Rule 5 — User Added to Security Group (standalone)
Triggers for any 4728 or 4732 event not already covered by Rule 3.  
Severity: **Medium**

### Rule 6 — New Account Created (standalone)
Triggers for any 4720 event not already covered by Rule 3.  
Severity: **Medium**

### Rule 7 — Service Installation (7045)
Triggers for any new service installation event.  
Severity: **Medium**

### Rule 8 — PowerShell Script Block (4104)
Recognises PowerShell logging events. Escalates to **High** if obfuscation indicators are present (e.g. `-enc`, `Invoke-Expression`, `DownloadString`, `base64`).

### Rule 9 — Account Deleted (4726)
Triggers for account deletion events.  
Severity: **Low**

---

## Default Thresholds

### Network Tool
| Rule | Default Threshold |
|------|------------------|
| High packet volume | 50 packets from one source |
| Possible host scanning | 10 unique destinations from one source |
| Possible port scanning | 10 unique destination ports to one host |
| High ICMP activity | 30 ICMP packets from one source |
| High DNS activity | 30 DNS packets from one source |
| Repeated communication | 40 packets between the same source–destination pair |

### Windows Tool
| Rule | Default Threshold |
|------|------------------|
| Repeated failed logons | 5 failures for the same account |

---

## Why Thresholds Are Not Universal

Thresholds in this toolkit are **educational defaults** chosen to make detections visible in small sample datasets. They are not universal security standards.

In a real environment:
- A database server may legitimately send thousands of packets per second
- A build server may generate hundreds of DNS queries during a software build
- An administrator may log in unsuccessfully several times in a row without any malicious intent
- A monitoring tool may ping every host on the network continuously

The appropriate threshold depends entirely on the environment, the role of the host, and the normal behaviour baseline. Always adjust thresholds to match your specific context.

---

## Sample Data

All sample files use fictional IP addresses (RFC 1918 private ranges and RFC 5737 documentation ranges) and fictional usernames. No real people, organisations, or infrastructure are represented.

### Network Samples

| File | Description | Expected Findings |
|------|-------------|------------------|
| `normal-traffic.csv` | Ordinary traffic between private hosts | Few or no alerts |
| `high-volume-traffic.csv` | One source sending 120+ packets | High Packet Volume alert |
| `mixed-soc-lab.csv` | Multiple patterns combined | Several findings including scanning, ICMP, repeated comms |

### Windows Samples

| File | Description | Expected Findings |
|------|-------------|------------------|
| `normal-windows-events.csv` | Normal user activity | Mostly informational |
| `password-guessing.csv` | 8 failed logins then success for jsmith | High: Possible Password Guessing Followed by Success |
| `account-persistence.csv` | Account created then added to Administrators | High: New Account Granted Privileges |
| `suspicious-admin-activity.csv` | Failed logins, new account, privilege grants, PowerShell, service install, log cleared | Multiple high and medium findings |

---

## Privacy Design

- All CSV parsing happens in the browser using the JavaScript `FileReader` API
- No data is sent to any server, API, or external service
- No analytics, tracking, cookies, or telemetry
- Files are not retained after the browser tab is closed
- No external JavaScript libraries are loaded
- No network requests are made during analysis (sample loading uses local `fetch` to the `samples/` folder only)

---

## Security Considerations

Because the toolkit parses user-supplied CSV files, the following protections are in place:

- **XSS prevention:** All values from CSV files are escaped before being inserted into the page. No raw HTML from CSV content is ever rendered.
- **No `innerHTML` with raw CSV data:** User-supplied strings are escaped using a dedicated `esc()` / `wEsc()` function before any DOM insertion.
- **No code execution:** CSV content is never evaluated or executed.
- **File type validation:** Only `.csv` files are accepted.
- **File size limit:** Files larger than 50 MB are rejected to prevent browser memory exhaustion.
- **No external requests during analysis:** The tool makes no outbound network calls during analysis.
- **No persistent storage:** Data is held only in memory and is cleared when the page is refreshed or closed.

---

## Accessibility

- Semantic HTML throughout (`header`, `main`, `footer`, `nav`, `article`, `section`)
- All interactive elements are keyboard accessible
- ARIA roles, labels, and `aria-expanded` attributes on collapsible cards
- `aria-live` regions for dynamic content updates
- Visible focus indicators
- Good colour contrast for all severity levels
- No information conveyed by colour alone — severity labels are always text
- Tables include `scope` attributes for screen reader compatibility

---

## Limitations

- **CSV only:** Version 1 does not support raw `.pcap`, `.pcapng`, or `.evtx` files
- **Column variation:** CSV column names differ between Wireshark versions and Windows builds; the tool handles common variations but may miss unusual exports
- **Timestamp parsing:** Date formats differ by locale; timestamp-based analysis may be limited
- **Port detection:** Port numbers in the network tool are extracted from the Wireshark Info field using pattern matching, which is not perfectly reliable
- **No persistent storage:** Refreshing the page clears all data
- **No cross-tool correlation:** Version 1 does not link network findings to Windows event findings
- **Large files may be slow:** CSVs with more than 50,000 rows may take several seconds to process in the browser
- **Single file analysis:** Each tool analyses one CSV at a time
- **Context limitations:** A single CSV export contains less information than a full SIEM, EDR, or IDS. Many findings require additional context to properly assess.
- **Not a replacement:** This toolkit does not replace Wireshark, IDS, SIEM, EDR, or professional SOC platforms

---

## False Positives

Many findings in this toolkit have legitimate explanations. Common causes of false positives include:

- **High packet volume:** Backup jobs, software updates, video conferencing, large file transfers
- **Many unique destinations:** Content delivery networks, update servers, distributed applications
- **High ICMP activity:** Network monitoring tools, ping-based health checks
- **High DNS queries:** Normal browsing behaviour, aggressive software update checks
- **Repeated failed logons:** Users forgetting passwords, stale service credentials, misconfigured applications
- **New accounts:** Routine onboarding, temporary project accounts
- **Privilege group changes:** Standard access provisioning
- **Log clearing:** Scheduled maintenance, automated log management

Always consider the most likely explanation before escalating.

---

## Educational Use

This toolkit is designed for:

- Cybersecurity students learning SOC analyst workflows
- Instructors demonstrating network and endpoint triage
- Portfolio demonstrations for job applications or interviews
- YouTube demonstrations and walkthroughs
- Self-study for CompTIA Security+, CySA+, or Blue Team fundamentals

**What you will learn using this toolkit:**
- How to read and interpret Wireshark packet data
- What key Windows Event IDs mean in practice
- How event correlation changes the significance of a finding
- How analysts apply structured thinking to ambiguous data
- How false positives arise and how to reason about them
- How investigation priority is assessed — not by certainty, but by risk and context

---

## Future Improvements

These features are documented for a future version and are **not** implemented in Version 1.

### Network Tool
- Direct `.pcap` and `.pcapng` file parsing
- TCP flag analysis (SYN flood detection)
- Time-window based detections (e.g. X packets within Y seconds)
- Traffic baselining and anomaly comparison
- Network relationship graphs
- GeoIP lookup for external IPs
- Threat intelligence enrichment
- DNS domain analysis
- Exportable SOC report (PDF or HTML)
- IDS-style rule engine

### Windows Tool
- Raw `.evtx` file parsing
- Sysmon event support
- PowerShell 4104 deeper analysis and deobfuscation
- Process tree visualisation
- MITRE ATT&CK technique mapping
- Timeline-based analysis with time windows
- Login time baselining (unusual hour detection)
- Scheduled task monitoring (Event 4698)
- Windows Defender event analysis
- Exportable incident report
- SIEM integration guidance

### Toolkit-Wide
- Cross-tool correlation (link network alerts to Windows events)
- Shared investigation workspace
- Multi-file analysis
- Configurable rule sets
- Dark/light mode toggle

---

## Video Demonstration Guide

Designed for recruiter or classroom demonstrations:

### Network Tool Demo
1. Load **Normal Traffic** → Point out low score, no significant alerts, ordinary traffic
2. Load **High-Volume Traffic** → Show the High Packet Volume alert, explain the threshold
3. Load **Mixed SOC Lab** → Show multiple findings — high volume, possible scanning, ICMP
4. Click an alert → Walk through the full explanation: observed activity, why it matters, benign explanations, next steps
5. Adjust a threshold → Show how re-analysis changes results
6. Key message: *“These are patterns worth investigating — not proof of an attack.”*

### Windows Tool Demo
1. Load **Normal Activity** → Show mostly informational findings, explain that successful logons are expected
2. Load **Password Guessing** → Show the high-severity finding, walk through the correlation: 8 failures then success
3. Load **Privilege Escalation** → Show the account-created-then-privileged sequence
4. Load **Mixed SOC Sample** → Show multiple correlated findings including log clearing
5. Click the Log Cleared alert → Explain why this always gets high priority
6. Key message: *“Individual events matter — but the real value comes from understanding how they relate to one another.”*

### Closing message:
> *“Detection tells an analyst where to look. Investigation determines what actually happened.”*

---

## Disclaimer

Educational network and endpoint triage toolkit. Alerts indicate activity worth investigating and do not prove malicious behaviour.

Only analyse traffic and logs from systems and networks you own or are authorised to monitor.

---

*SOC Triage Toolkit — Version 1.0 — Educational use only*
