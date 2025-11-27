## 📋 Scenario Overview

**Objective**: Simulate an external attacker attempting to gain unauthorized access to target system or network by systematically guessing valid login credentials

**MITRE ATT&CK Mapping**:

- Tactic: Credential Access (TA0006)
- Technique: Brute Force (T1110)
- Sub-technique: Password Guessing (T1110.001)

**Difficulty**: Beginner  
**Estimated Time**: 30 minutes (attack + analysis)

## 🎯 Learning Goals

- Detect authentication-based attacks
- Analyze failed login patterns
- Create alerting thresholds
- Understand attacker reconnaissance behavior

## 🏗️ Environment Setup

### Target System

- Windows 10
- RDP enabled (port 3389)
- Test account: `client-lab` / `Password123`

### Attack System

- Kali Linux
- Tools: Hydra

### Prerequisites

- Target VM sending auth logs to SIEM
- Network connectivity between attacker and target

## ⚔️ Attack Execution

### Step 1: Reconnaissance

```bash
# From Kali machine
nmap -p 3389 <WINDOWS_IP_ADDRESS>
```
_You can get the IP address from the command prompt using_ `ipconfig`

### Step 2: Prepare Wordlist

```bash
# Use a small custom wordlist for demo
cat > passwords.txt << EOF
password
Password123
admin
root
123456
testuser
Summer2024!
EOF
```

### Step 3: Execute Brute Force

```bash
# Using Hydra
hydra -l testuser -P passwords.txt 
```

### Step 4: Successful Authentication

```bash
# After successful guess
ssh testuser@192.168.1.100
```

## 📊 Expected Log Evidence

### Auth Logs (Linux Target)

Location: `/var/log/auth.log`

```
Jan 15 14:23:11 ubuntu-server sshd[1234]: Failed password for testuser from 192.168.1.50 port 45678 ssh2
Jan 15 14:23:13 ubuntu-server sshd[1235]: Failed password for testuser from 192.168.1.50 port 45679 ssh2
Jan 15 14:23:15 ubuntu-server sshd[1236]: Failed password for testuser from 192.168.1.50 port 45680 ssh2
...
Jan 15 14:23:45 ubuntu-server sshd[1245]: Accepted password for testuser from 192.168.1.50 port 45689 ssh2
```

### Key Indicators

- Multiple failed authentication attempts
- Same source IP address
- Sequential connection attempts
- Short time intervals between attempts
- Eventual successful login from same IP

## 🔍 SIEM Detection

### Kibana/Elasticsearch Query

```
event.category: "authentication" AND 
event.outcome: "failure" AND 
source.ip: * 
| stats count by source.ip, user.name 
| where count > 5
```

### Splunk Query

```
index=linux sourcetype=linux_secure "Failed password"
| stats count by src_ip, user
| where count > 5
```

### Detection Logic

- **Alert Threshold**: 5+ failed attempts within 5 minutes from single IP
- **Severity**: Medium → High (if successful login follows)

## 🚨 Sample Detection Rule

```yaml
title: SSH Brute Force Attack Detected
id: ssh-bruteforce-001
status: experimental
description: Detects multiple failed SSH authentication attempts indicating brute force attack
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event.type: authentication_failure
    service.name: sshd
  timeframe: 5m
  condition: selection | count(source.ip) > 5
level: high
tags:
  - attack.credential_access
  - attack.t1110.001
```

## 🔎 Investigation Steps

### 1. Initial Triage

- Identify the source IP address
- Check OSINT (AbuseIPDB, GreyNoise) for IP reputation
- Determine if any accounts were compromised

### 2. Timeline Analysis

```
1. 14:23:11 - First failed attempt detected
2. 14:23:11-14:23:43 - 32 failed attempts over 32 seconds
3. 14:23:45 - Successful authentication
4. 14:23:45-14:25:30 - User session active
```

### 3. Scope Assessment

- Check for lateral movement from compromised account
- Review commands executed during session
- Identify any privilege escalation attempts

### 4. IOCs (Indicators of Compromise)

- Source IP: `192.168.1.50`
- Compromised Account: `testuser`
- Attack Duration: ~35 seconds
- Success Rate: 1/33 attempts

## 🛡️ Response Actions

### Immediate Actions

1. Block source IP at firewall
2. Force password reset for affected account
3. Review account permissions and access

### Containment

```bash
# Block IP using iptables
sudo iptables -A INPUT -s 192.168.1.50 -j DROP

# Disable compromised account
sudo usermod -L testuser

# Review active sessions
who
last -20
```

### Remediation

- Implement SSH key authentication
- Deploy fail2ban for automated blocking
- Enable MFA if available
- Review and strengthen password policy

## 📈 Metrics & KPIs

- **Time to Detect**: < 1 minute
- **Time to Alert**: < 2 minutes
- **Time to Respond**: < 10 minutes
- **False Positive Rate**: Document after tuning

## 🎓 Lessons Learned

### What Worked Well

- Detection rule triggered correctly
- Clear log evidence available
- Easy to trace attack timeline

### Improvements Needed

- Reduce detection threshold (currently 5 attempts)
- Add automated blocking
- Implement rate limiting at network level

### Skills Developed

- Log analysis and pattern recognition
- Detection rule creation
- Incident response procedures
- Timeline reconstruction

## 📚 Additional Resources

- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [SSH Hardening Guide](https://www.ssh.com/academy/ssh/hardening)

## 🔄 Variations to Try

1. **Easy**: Increase failed attempts threshold to 10
2. **Medium**: Add IP address rotation to evade detection
3. **Hard**: Combine with user enumeration (different usernames)
4. **Expert**: Low-and-slow attack (1 attempt per minute over hours)