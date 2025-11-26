# Home SOC Lab with Ubuntu SIEM

A hands-on home Security Operations Center (SOC) lab built with VirtualBox, using an Ubuntu-based SIEM to collect, correlate, and analyze security logs from multiple virtual machines. This project is designed to demonstrate SOC workflows such as log ingestion, alerting, and basic threat hunting in an isolated environment.

---

## Table of Contents

- [Overview](#overview)  
- [Architecture](#architecture)  
- [Lab Objectives](#lab-objectives)  
- [Tech Stack](#tech-stack)  
- [Setup and Installation](#setup-and-installation)  
- [SIEM Configuration](#siem-configuration)  
- [Generating and Analyzing Events](#generating-and-analyzing-events)  
- [Repository Structure](#repository-structure)  
- [Future Improvements](#future-improvements)  
- [Disclaimer](#disclaimer)  

---

## Overview

This project simulates a small SOC environment running entirely on a single host machine using Oracle VirtualBox.  
An Ubuntu virtual machine hosts the SIEM platform, which collects logs from other virtual machines that represent endpoints and infrastructure components on a virtual network.

You can adapt this lab to practice skills such as log analysis, detection engineering, threat hunting, and incident documentation.

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

---

## Setup and Installation

This section explains how someone else can recreate the environment on their own machine.

### Prerequisites

- Hardware capable of running multiple VMs (recommended: multi-core CPU, 16 GB+ RAM, and sufficient disk space).  
- Virtualization enabled in BIOS/UEFI.  
- Oracle VirtualBox installed on the host system.  
- ISO images for Ubuntu and any additional operating systems used as endpoints.

### Step 1: Create the Virtual Network

- Define one or more internal or host-only networks in VirtualBox for the SOC lab.  
- Decide on IP ranges and basic addressing for each VM.  
- Optionally add a NAT adapter for controlled outbound internet access if required for updates or package installation.

### Step 2: Build the SIEM VM (Ubuntu)

- Create a new VM in VirtualBox and install Ubuntu as the SIEM host.  
- Assign a static IP address within the lab network.  
- Apply basic hardening measures (update packages, configure a non-root user, enable firewall rules as appropriate).  
- Install and configure your chosen SIEM stack:
  - Core services (e.g., Elasticsearch, database, or equivalent back end).
  - Web interface and management console.
  - Any bundled agents or managers required for endpoint integration.

### Step 3: Build Endpoint VMs

- Create one or more additional VMs (Linux/Windows) to act as monitored endpoints.  
- Join each endpoint to the same VirtualBox network as the SIEM.  
- Configure basic system logging and time synchronization.

---

## SIEM Configuration

This section documents how logs get from endpoints into your SIEM.

Key configuration tasks:

- **Agent/forwarder installation**  
  - Install SIEM agents or log shippers on each endpoint.  
  - Point them to the SIEM VM’s IP/hostname and relevant port(s).

- **Log sources and pipelines**  
  - Define data sources or inputs in the SIEM (e.g., syslog, Windows event logs, security logs).  
  - Configure pipelines, index patterns, or streams so logs are parsed and stored correctly.

- **Dashboards and visualizations**  
  - Create or customize dashboards to monitor authentication activity, process creation, network events, or security alerts.  
  - Include screenshots in the `/docs` folder to show key dashboards.

- **Alerting and detection rules**  
  - Implement a small set of detection rules, such as:
    - Multiple failed logons in a short window.  
    - New administrative account creation.  
    - Unusual process executions or services.

---

## Generating and Analyzing Events

To demonstrate the lab, this section walks through how to create activity and then investigate it.

Example exercises:

- **Authentication scenarios**
  - Perform normal logins and logouts on endpoints.  
  - Intentionally generate failed logins or simple brute-force attempts to trigger alerts.

- **Reconnaissance and scanning**
  - Run a basic port scan from one VM to another and observe resulting events in the SIEM.

- **Process and malware simulation**
  - Execute benign tools that resemble suspicious behavior (e.g., scripting tools, admin utilities).  
  - Analyze how these events appear in logs and dashboards.

For at least one scenario, document:

1. How the activity was generated.  
2. Which logs appeared in the SIEM.  
3. Any alerts that were triggered.  
4. The investigation steps (queries, filters, pivoting across data).  
5. The final assessment and recommended response.

This incident-style write-up is valuable for interviews and portfolio reviews.

---

## Repository Structure

A suggested structure for this project:

>>>>>>> origin/main
