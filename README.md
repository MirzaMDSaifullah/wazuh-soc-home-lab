# Wazuh SOC Home Lab

A hands-on Security Operations Center (SOC) home lab built to gain practical experience into SIEM deployment, endpoint monitoring, detection engineering, log analysis, and security alert investigation.

## Project Overview

This project implements a Wazuh-based SIEM environment with an Ubuntu Wazuh server and a Windows endpoint monitored using the Wazuh Agent and Sysmon.

The lab was used to generate controlled security events, investigate logs, create custom detection rules, map detections to the MITRE ATT&CK framework, and build a custom SOC monitoring dashboard.

## Lab Architecture

- **Wazuh Manager, Indexer and Dashboard:** Ubuntu Linux VM
- **Monitored Endpoint:** Windows
- **Endpoint Agent:** Wazuh Agent
- **Advanced Windows Telemetry:** Sysmon
- **Virtualization:** Oracle VirtualBox
- **Network:** Host-only virtual network

### Data Flow

Windows Endpoint  
→ Wazuh Agent + Sysmon  
→ Wazuh Manager  
→ Wazuh Indexer  
→ Wazuh Dashboard  
→ Custom SOC Detection Dashboard

## Technologies Used

- Wazuh SIEM
- Sysmon
- Windows Event Logs
- Ubuntu Linux
- VirtualBox
- PowerShell
- XML-based Wazuh custom rules
- MITRE ATT&CK

## Detection Scenario 1: Multiple Failed Login Attempts

Multiple Windows authentication failures were generated into the controlled lab environment.

A custom Wazuh correlation rule was created to detect multiple failed authentication attempts within a defined time window.

**Custom Rule ID:** `100101`  
**Alert Level:** `12`  
**MITRE ATT&CK:** `T1110 - Brute Force`

```xml
<rule id="100101" level="12" frequency="3" timeframe="60">
  <if_matched_sid>60122</if_matched_sid>
  <description>
    Custom Detection: Multiple Windows failed login attempts - Possible brute force
  </description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
