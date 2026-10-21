# Endpoint Defense & Telemetry Engineering Utilities

A curated collection of defensive PowerShell utilities, host security auditing tools, and event analysis scripts engineered for enterprise system hardening, Windows Filtering Platform (WFP) network telemetry parsing, and Endpoint Detection and Response (EDR) rule validation.

---

## Overview & Operational Purpose

This repository provides host-level defense tooling to enhance enterprise endpoint visibility, audit baseline administrative compliance, and optimize event telemetry collection for security analysis and SIEM ingestion.

### Primary Focus Areas
- **Network Telemetry & Isolation:** Extracting and parsing low-level Windows Filtering Platform (WFP) network blocking events (Event IDs 5157 & 5152)[cite: 3], resolving runtime FilterRTIDs to netsh display names[cite: 3], and aggregating outbound connection blocks by application and destination[cite: 3].
- **System Hardening & Compliance:** Auditing core Windows security controls—including Local Security Authority (LSA) RunAsPPL memory protection[cite: 1], registry-level PowerShell Script Block Logging enforcement[cite: 1], and User Account Control (UAC) administrative consent behavior[cite: 1].
- **Process Telemetry & Execution Auditing:** Streamed pipeline parsing of active process command lines using CIM (`Win32_Process`)[cite: 2] to identify obfuscated PowerShell flags (`-EncodedCommand`)[cite: 2] and administrative shells running out of temporary user directories (`%TEMP%`)[cite: 2].

---

## Repository Structure

| File | Subsystem | Description & Operational Purpose |
| :--- | :--- | :--- |
| `Get-WfpBlockedOutbound.ps1` | Network / Firewall | Queries Security Event 5157/5152[cite: 3], maps `\Device\HarddiskVolume` paths to drive letters[cite: 3], resolves WFP filter runtime IDs[cite: 3], and exports aggregated CSV summaries[cite: 3]. |
| `Audit-HostHardening.ps1` | OS Baseline | Audits LSA RunAsPPL configuration[cite: 1], PowerShell Script Block Logging policies in HKLM[cite: 1], and UAC Admin Consent behavior[cite: 1]. |
| `Get-ProcessTelemetry.ps1` | Process / Execution | Queries `Win32_Process` via pipeline[cite: 2] to identify encoded command-line execution[cite: 2] and LOLBin shells executing out of `AppData\Local\Temp`[cite: 2]. |

---

## Prerequisites & Requirements

- **Operating System:** Windows 10/11, Windows Server 2019+
- **Privileges:** Administrator privileges required for reading the `Security` event log[cite: 3], querying WFP filter states via `netsh`[cite: 3], and evaluating system registry locations[cite: 1].
- **PowerShell:** PowerShell 5.1 or PowerShell 7+

---

## Usage Examples

### 1. WFP Network Event Audit & Export
```powershell
# Audit WFP outbound blocks from the past 4 hours, resolve active filter names, and export CSVs
.\Get-WfpBlockedOutbound.ps1 -Hours 4 -ResolveFilters -ExportPath "C:\Temp\WFP"
