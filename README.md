# Home SOC Lab with SIEM Logging

A hands-on home Security Operations Center (SOC) lab built with VirtualBox, using an Ubuntu-based SIEM to collect, correlate, and analyze security logs from multiple virtual machines. This project is designed to demonstrate SOC workflows such as log ingestion, alerting, and basic threat hunting in an isolated environment.

---
## Overview

This project simulates a small SOC environment running entirely on a single host machine using Oracle VirtualBox.  

An Ubuntu virtual machine hosts the SIEM platform, which collects logs from other virtual machines that represent endpoints and infrastructure components on a virtual network.

This lab to showcases skills such as log analysis, detection engineering, threat hunting, and incident documentation.

---
## Architecture

The lab is built around a VirtualBox virtual network that isolates all SOC components from the physical home network.

Core components:
- **Host machine**: Your physical PC or laptop providing compute, RAM, and storage for all virtual machines.
- **SIEM VM (Ubuntu)**: Central log collection and analysis server running your chosen SIEM stack.
- **Endpoint VMs**: One or more Linux and/or Windows machines configured to forward logs to the SIEM.
- **Optional infrastructure**: A virtual firewall/router VM and/or intentionally vulnerable targets for generating security-relevant events.

A diagram (recommended in your `/diagrams` folder) should show:
- Network segments and IP addressing
- Log and agent data flow into the SIEM
- Management access paths (e.g., SSH/RDP/GUI to the SIEM and endpoints)

---

## Lab Objectives

This lab is intended to:

- Recreate a small, realistic network where a SOC analyst can practice monitoring and investigation workflows.  
- Configure a centralized SIEM on Ubuntu to ingest, normalize, and visualize logs from multiple sources.  
- Build and test basic detection rules (for example, failed login bursts or suspicious process execution).  
- Document at least one end-to-end incident investigation from event generation to final conclusion.

These objectives make the project suitable for a portfolio, resume, or interview discussion.

---

## Tech Stack

You can adjust tools to your preference; below is the general stack this lab assumes:

- **Virtualization**
  - Oracle VirtualBox for hosting and networking all lab virtual machines.

- **Operating Systems**
  - Ubuntu (server or desktop) as the SIEM host.
  - One or more additional Linux and/or Windows VMs as endpoints.

- **SIEM Platform**
  - An Ubuntu-based SIEM stack (for example: Wazuh, ELK/Elastic Stack, Graylog, or similar open-source tooling).

- **Agents and Logging Tools**
  - OS-level logging (e.g., syslog on Linux, event logs on Windows).
  - Endpoint agents/log shippers (e.g., Wazuh agents, Beats, or other supported agents for your SIEM).
  - Optional: Enhanced logging such as Sysmon on Windows or auditd on Linux.





## Repository Structure

A suggested structure for this project:

>>>>>>> origin/main
