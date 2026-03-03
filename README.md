# DNS-Log-Analysis-Splunk
Practical DNS log analysis in Splunk using Zeek data to simulate real-world SOC investigations and DNS threat detection workflows.

# 🔎 DNS Log Analysis Lab – Splunk

## 📌 Overview

This project demonstrates the ingestion and analysis of Zeek DNS logs using Splunk.

The lab focuses on DNS traffic monitoring, query analysis, source host identification, and SOC-style threat hunting using SPL (Search Processing Language).

The goal of this project was to simulate real-world Tier 1 SOC investigation workflows by analyzing DNS telemetry for abnormal behavior and potential security threats.

---

## 🏗️ Lab Environment

**SIEM Platform:** Splunk Enterprise  
**Data Source:** Zeek DNS JSON Logs  
**Index Used:** main  
**Source Type:** json  
**Total Events Analyzed:** ~1,200  

**Key Log Fields:**

- ts (timestamp)  
- id.orig_h (source IP)  
- id.resp_h (DNS server IP)  
- qtype (DNS record type)  
- query (domain requested)  
- answers (resolved IP)  
- rcode (response code)  
- rtt (round trip time)  

---

## 📥 Data Ingestion

The DNS log file (`dns_logs.json`) was uploaded into Splunk via:

Settings → Add Data → Upload

Configuration:

- Source Type: `json`  
- Index: `main`  

Verification:

```spl
index=main | head 5
```

Field extraction validation:

```spl
index=main source="*dns_logs.json*"
| spath
| table query qtype id.orig_h id.resp_h rcode
```

---

## 🔍 Task 1: Most Frequently Queried Domains

### SPL Used

```spl
index=main source="*dns_logs.json*"
| spath
| stats count by query
| sort -count
```

### Findings

| Domain          | Query Count |
|----------------|------------|
| google.com     | 278        |
| printer.local  | 278        |

### Analysis

- `google.com` reflects normal web browsing traffic.
- `printer.local` indicates internal device discovery or local DNS resolution.

No suspicious high-frequency domains were identified.

---

## 🔍 Task 2: Most Active Source IPs

### SPL Used

```spl
index=main source="*dns_logs.json*"
| spath
| stats count by id.orig_h
| sort -count
```

### Findings

| Source IP       | DNS Queries Generated |
|----------------|----------------------|
| 192.168.1.10   | 226                  |
| 192.168.1.18   | 226                  |
| 192.168.1.21   | 224                  |

### Analysis

DNS traffic was evenly distributed among internal hosts.

No single endpoint generated abnormally high query volume, reducing suspicion of DNS beaconing, DGA activity, or automated malware communication.

---

## 🔍 Task 3: DNS Query Type Breakdown

### SPL Used

```spl
index=main source="*dns_logs.json*"
| spath
| stats count by qtype
```

### Query Types Observed

| Query Type | Description                |
|------------|----------------------------|
| A          | IPv4 resolution            |
| AAAA       | IPv6 resolution            |
| CNAME      | Alias record               |
| PTR        | Reverse DNS lookup         |

### Analysis

- A records were the most frequent, which is expected in most enterprise environments.
- AAAA records reflected IPv6 resolution attempts.
- CNAME records indicated domain aliasing.
- PTR records were observed at lower frequency, consistent with normal reverse lookups.

The distribution aligned with expected enterprise DNS behavior.

---

## 🚨 Additional Threat Hunting Performed

### Rare Domains

```spl
index=main source="*dns_logs.json*"
| spath
| stats count by query
| sort count
```

Purpose: Identify low-frequency domains that may indicate suspicious or newly generated domains.

---

### Failed DNS Lookups (NXDOMAIN Detection)

```spl
index=main source="*dns_logs.json*"
| spath
| search rcode!=0
| stats count by query rcode
```

Purpose: Detect potential Domain Generation Algorithm (DGA) activity or failed malicious domain lookups.

---

### Unique Domains Per Host

```spl
index=main source="*dns_logs.json*"
| spath
| stats dc(query) as unique_domains by id.orig_h
| sort -unique_domains
```

Purpose: Identify hosts querying an unusually high number of unique domains.

---

## 🎯 Skills Demonstrated

- DNS traffic analysis in Splunk  
- Zeek log interpretation  
- JSON field extraction using `spath`  
- SPL aggregation using `stats`  
- Identifying DNS anomalies  
- Basic DNS threat hunting methodology  
- SOC investigation workflow simulation  

---

## 🔚 Conclusion

Through this project, I successfully:

- Ingested structured DNS logs into Splunk  
- Extracted and analyzed key DNS fields  
- Identified high-frequency domains and top DNS-generating hosts  
- Evaluated DNS query type distributions  
- Conducted basic threat hunting for suspicious DNS activity  

This lab reflects practical SOC-level experience analyzing DNS telemetry in a SIEM environment and reinforces my ability to investigate DNS-based threats using Splunk.
