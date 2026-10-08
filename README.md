# Endpoint Defense & Telemetry Engineering Utilities

A curated collection of defensive PowerShell utilities, host security auditing tools, and event analysis scripts designed for enterprise system hardening, Windows Filtering Platform (WFP) network telemetry parsing, and Endpoint Detection and Response (EDR) rule validation.

## Overview & Operational Purpose

This repository hosts open-source tools aimed at improving host-level visibility, auditing administrative security baselines, and optimizing event telemetry ingestion into enterprise SIEM platforms.

### Key Functional Focus Areas
- **Network Telemetry & Isolation:** Extracting and parsing low-level Windows Filtering Platform (WFP) connection logs (Event IDs 5156, 5157, 5158) to audit host firewall enforcement and outbound traffic boundaries.
- **System Hardening & Compliance:** Auditing core operating system security controls—including Local Security Authority (LSA) PPL protection, PowerShell Script Block Logging, and User Account Control (UAC) administrative policies—against CIS/NIST standards.
- **Process Telemetry & Detection Engineering:** Monitoring active process trees to identify suspicious parent-child execution lineages, encoded PowerShell payloads, and LOLBin activity executing from user temporary directories.

---

## Repository Structure

| File | Subsystem | Description & Primary Use Case |
| :--- | :--- | :--- |
| `Get-WFPNetworkEvents.ps1` | Network / Firewall | Queries WFP logs to extract blocked/allowed connection events, filter IDs, and layer identifiers for network isolation verification. |
| `Audit-HostHardening.ps1` | OS / Baseline | Audits LSA RunAsPPL configuration, registry-level PowerShell script block logging, and UAC elevation policies. |
| `Get-ProcessTelemetry.ps1` | Process / Execution | Inspects running process command lines for `-EncodedCommand` flags and identifies administrative shells running out of `%TEMP%` directories. |

---

## Prerequisites & Execution Setup

- **Operating System:** Windows 10/11, Windows Server 2019+
- **Execution Rights:** Administrative elevation (Run as Administrator) required for low-level WFP security event log access and CIM queries.
- **PowerShell Version:** PowerShell 5.1 or PowerShell 7+

### Quick Start Example

```powershell
# Clone the repository
git clone [https://github.com/YOUR-USERNAME/endpoint-defense-telemetry.git](https://github.com/YOUR-USERNAME/endpoint-defense-telemetry.git)
cd endpoint-defense-telemetry

# Execute host baseline security check
.\Audit-HostHardening.ps1

# Audit process command-line telemetry
.\Get-ProcessTelemetry.ps1
