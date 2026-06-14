# Cybersecurity Risk Register CLI

A Python command-line tool for identifying, scoring, and prioritizing cybersecurity risks using a standard risk management methodology.

## Overview

Organizations face risks such as phishing attacks, ransomware, vendor breaches, and cloud misconfigurations. This tool helps document those risks, calculate risk scores, evaluate controls, and prioritize remediation efforts.

Built as a portfolio project to demonstrate cybersecurity risk management, GRC, IT audit, and Python development skills.

## Features

* Calculate risk scores using **Likelihood × Impact**
* Assess residual risk after controls are applied
* Rank risks by severity
* Generate risk reports with recommendations
* Import risks from CSV files
* Add risks interactively through the CLI
* View risks on a color-coded heat map
* Includes 14 built-in cybersecurity risk scenarios

## Risk Scoring

Each risk is scored using:

```text
Risk Score = Likelihood × Impact
```

| Score | Description   |
| ----- | ------------- |
| 1–5   | Low Risk      |
| 6–10  | Moderate Risk |
| 11–15 | High Risk     |
| 16–25 | Critical Risk |

Higher scores indicate higher-priority risks.

## Built-In Examples

The tool includes realistic cybersecurity scenarios such as:

* Publicly exposed cloud storage
* Missing multi-factor authentication (MFA)
* Vendor data breaches
* Ransomware attacks
* Phishing campaigns
* Unpatched systems
* Legacy software vulnerabilities

## Installation

### Requirements

* Python 3.8+
* No external dependencies

### Run

```bash
python risk_register.py
```

## Skills Demonstrated

**Cybersecurity**

* Risk Assessment
* Risk Management
* Residual Risk Analysis
* Security Controls
* ISO 31000 Principles
* Governance, Risk & Compliance (GRC)

**Technical**

* Python
* Object-Oriented Programming
* CSV Processing
* Report Generation
* Data Visualization
* CLI Development

## Project Purpose

This project demonstrates how cybersecurity risks are identified, scored, mitigated, and reported in real-world organizations. It was built as a portfolio project for cybersecurity, GRC, risk management, and IT audit roles.

## Future Improvements

* PDF report export
* Database integration
* Web dashboard
* Risk trend tracking
* User authentication

## License

This project is available for educational and portfolio purposes.
