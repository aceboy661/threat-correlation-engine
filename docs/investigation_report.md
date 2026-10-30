# Investigation Report - Threat Correlation Engine

**Date:** October 30, 2026  
**Analyst:** Marlon Lonmon  
**Project:** Threat Correlation Engine

---

## Summary
The correlation engine analyzed authentication, process, and network logs together. Multiple related suspicious signals were detected, resulting in a high-confidence alert.

---

## Findings

### 1. Failed Login Activity
- 4 failed login attempts detected from IP 203.0.113.50
- Targeted accounts: admin and root

### 2. Suspicious Process Execution
- Processes launched from unusual locations: `/tmp/update.bin` and `/dev/shm/miner`
- These locations are commonly used by malware

### 3. Unusual Network Activity
- Connections observed on high-risk ports 4444 and 12345

---

## Correlation Result
**Score: 3/3**  
All three signal types were present, indicating a likely coordinated attack or post-compromise activity.

**Severity:** High

---

## Recommendation
- Block the source IP 203.0.113.50
- Investigate and terminate the suspicious processes
- Review the affected host for persistence and lateral movement
- Correlate with additional log sources if available

---

## Conclusion
This project demonstrates multi-log correlation and higher-confidence detection, which are key skills for SOC and Detection Engineering roles.
