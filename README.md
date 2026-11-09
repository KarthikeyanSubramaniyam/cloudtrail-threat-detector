# CloudTrail Threat & Adversary Behavior Detector

<p align="center">
  <img src="https://img.shields.io/badge/Security-Defensive_Auditor-blue?style=flat" alt="Type">
  <img src="https://img.shields.io/badge/Status-Architectural_Showcase-success?style=flat" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python">
</p>

> 🔒 **Technical Showcase & Architecture Specification**  
> *This repository provides public architectural documentation, system specifications, and implementation summaries. Full production source code, internal test suites, and proprietary algorithms are maintained in a secure private repository.*

---

## 📌 Executive Summary

**Category**: Threat Detection & SOC Operations  
**Tech Stack**: `Python 3.10+ · AWS CloudTrail · MITRE ATT&CK · Threat Detection`  

Rule-based and behavioral detection engine identifying attacker reconnaissance, credential access, and defense evasion in AWS audit streams.

---

## 🎯 The Problem It Solves

Adversaries targeting cloud environments execute specific reconnaissance and defense evasion API calls (e.g. stopping CloudTrail, disabling GuardDuty, creating unauthorized access keys) that must be alerted on instantly.

---

## ⚙️ How the Engine Works

1. **Continuous Event Stream Processing**: Parses AWS CloudTrail JSON records from multi-region storage buckets.
2. **Adversary TTP Signatures**: Matches events against curated threat detection rules mapped to MITRE ATT&CK for Cloud:
   - **Defense Evasion**: `StopLogging`, `DeleteTrail`, `DeleteDetector`, `UpdateDetector`
   - **Persistence / Credential Access**: `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`
   - **Reconnaissance**: `DescribeInstances` bursts, `ListBuckets` from unknown IPs, `GetCallerIdentity`
3. **Geo-IP & Anomaly Verification**: Flags administrative actions executed outside approved corporate CIDR ranges or via Tor/VPN exit nodes.
4. **Alert Prioritization**: Assigns severity scores (LOW to CRITICAL) with rich contextual metadata.

---

## 🚀 Key Capabilities

- Instant alerting on CloudTrail or GuardDuty tampering attempts
- Detection of root account usage and unauthorized access key generation
- MITRE ATT&CK technique mapping for SOC analysts
- Zero false-positive design for high-severity administrative events

---

## 🏗️ System Data Flow & Architecture

```
+-----------------------------------+
|  Target Input / Configuration    |
|  (JSON Snapshots / Policies)      |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  1. Schema Normalization Engine   |
|  Validates types & formats        |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  2. Core Analytical Pipeline      |
|  Heuristic rule evaluation,       |
|  invariant checks & drift diffs   |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  3. Risk Classification           |
|  Assigns severity: INFO / HIGH    |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  4. Structured Findings & Report  |
|  Root cause, evidence &           |
|  actionable remediation steps     |
+-----------------------------------+
```

---

## 📄 Findings Output Structure

The engine generates structured, machine-parsable JSON reports adhering to this standard audit schema:

```json
{
  "results": [
    {
      "resource": "resource-identifier",
      "severity": "HIGH",
      "check": "CHECK_IDENTIFIER",
      "detail": "Descriptive analysis of the identified security posture issue.",
      "remediation": "Actionable step-by-step guidance to restore compliant state.",
      "evidence": {
        "observed_field": "value",
        "required_policy": "enforced_policy"
      }
    }
  ],
  "count": 1,
  "scope": "Comprehensive defensive security audit"
}
```

---

## 🔒 Source Code & Enterprise Inquiries

To protect proprietary intellectual property and client operational security:
* **Public Repository**: Contains comprehensive architecture specifications, schemas, and design overviews.
* **Private Repository**: Contains the complete production implementation, continuous integration pipelines, and full regression test suites.

For architectural questions or enterprise inquiries, connect via [LinkedIn](https://www.linkedin.com/in/karthikeyansubramaniam04/) or visit the [Portfolio Site](https://karthikeyansubramaniyam.github.io).
