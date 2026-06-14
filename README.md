# Risk Register CLI

**A simple Python tool that helps organizations identify, score, and prioritize cybersecurity risks.**

---

## What is this?

Every organization faces cybersecurity risks. A server that could be compromised, a vendor that could leak data, or an employee who clicks a phishing email.

This tool helps track those risks, calculate how serious they are, and determine which ones should be addressed first.

---

## How it works

Each risk is scored using two factors:

* **Likelihood** – How likely is the risk to occur? (1–5)
* **Impact** – How severe would the consequences be? (1–5)

The two values are multiplied together to produce a risk score:

```text
Risk Score = Likelihood × Impact
```

Higher scores indicate higher-priority risks.

The tool also allows security controls (such as MFA, backups, or security awareness training) to be applied, reducing the overall risk. The remaining risk is known as **residual risk**.

---

## Features

* Scores risks using a standard risk assessment methodology
* Calculates residual risk after controls are applied
* Displays a color-coded risk heat map
* Ranks risks from highest to lowest priority
* Generates reports with findings and recommendations
* Imports risk data from CSV files
  
---

### Requirements

* Python 3.8 or higher
* No additional libraries required

## Built-In Examples

Some of the included risk scenarios:

* AWS cloud storage exposed to the internet
* Missing multi-factor authentication (MFA)
* Vendor data breaches
* Ransomware attacks
* Phishing and business email compromise
* Weak access controls and security misconfigurations

---

## Why I Built This

This project was created to demonstrate practical cybersecurity risk management skills and Python development.

It showcases:

* Risk identification and assessment
* Risk scoring and prioritization
* Security control evaluation
* Report generation and documentation
* Clean, maintainable Python code

---

### Cybersecurity Skills

* Risk Management
* Risk Prioritization
* Security Controls

### Technical Skills

* Python
* CSV Processing
* Data Visualization
* CLI Application Development
