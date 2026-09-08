# Log-analzyer
A Python-based cybersecurity log analyzer that processes login data, detects suspicious authentication activity, identifies repeated failed login attempts, and calculates a risk score to help assess potential brute-force attacks.

## Overview

**Cyber Log Analyzer** processes login data from a CSV file and performs basic security analysis. It identifies repeated failed login attempts, suspicious IP addresses, and potentially targeted user accounts.

The program also calculates a **risk score from 0–100** and assigns an overall security level based on the activity detected.

## Features

* Analyze login activity
* Count successful and failed login attempts
* Detect suspicious IP addresses
* Detect accounts receiving repeated failed login attempts
* Set a custom failed-login alert threshold
* Calculate a cybersecurity risk score
* Assign Low, Medium, or High risk levels
* Generate a final investigation summary

## Technologies

* **Python**
* **Pandas**
* **CSV**

## Project Structure

```text
Cyber-Log-Analyzer/
│
├── analyzer.py
├── login_logs.csv
└── README.md
```

## How to Run

### 1. Install Pandas

```bash
pip install pandas
```

### 2. Run the analyzer

```bash
python analyzer.py
```

### 3. Enter the alert threshold

When prompted, enter the number of failed login attempts that should trigger an alert.

Example:

```text
How many failed attempts should trigger an alert? 3
```

## Example Detection

The analyzer can identify activity such as:

```text
ALERT: 192.168.1.55 had 5 failed login attempts

ALERT: admin had 5 failed login attempts
```

It then calculates an overall risk score:

```text
Risk Score: 80 /100
  HIGH RISK

Possible brute-force attack detected.
```

## Purpose

This project was created to practice applying **Python programming and data analysis to cybersecurity**.

It demonstrates how security logs can be processed to identify patterns that may indicate suspicious authentication activity.

## Future Improvements

Planned improvements include:

* Wazuh SIEM integration
* JSON log support
* MITRE ATT&CK technique mapping
* Automated SOC investigation reports
* Real-time log monitoring
* More advanced threat detection
* Graphical dashboard
* Windows and Linux log support

## Skills Demonstrated

**Python • Pandas • Log Analysis • Threat Detection • Risk Scoring • Cybersecurity • SOC Fundamentals**
