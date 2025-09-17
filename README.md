# Web Application Security Assessment Report – SQL Injection (SQLi)

This repository contains my **Web Application Security Assessment Report**, which focuses on identifying, demonstrating, and mitigating a **SQL Injection (SQLi)** vulnerability in a sample web application. It documents the full process from discovery to proof-of-concept exploitation and provides recommendations for remediation.

---

## Table of Contents
- [Introduction](#introduction)
- [Scope](#scope)
- [Vulnerability Description](#vulnerability-description)
- [Affected URL & Parameters](#affected-url--parameters)
- [Proof of Concept (PoC)](#proof-of-concept-poc)
- [Business Impact](#business-impact)
- [Remediations & Recommendations](#remediations--recommendations)
- [References](#references)
- [Disclaimer](#disclaimer)

---

## Introduction
This assessment highlights a **SQL Injection vulnerability** in a deliberately vulnerable web application hosted at `http://testphp.vulnweb.com/`.  
The goal was to:
- Identify insecure coding practices.
- Demonstrate how SQL Injection can bypass logic and expose sensitive data.
- Recommend mitigations to prevent such vulnerabilities.

---

## Scope
- **In Scope:** Testing the `listproducts.php` endpoint for SQL Injection.  
- **Exclusions:** No denial-of-service testing, no social engineering, and no unauthorized attacks on systems beyond the test environment.  

---

## Vulnerability Description
**SQL Injection (SQLi)** occurs when user-supplied input is improperly sanitized and directly embedded into SQL queries. Attackers can manipulate these queries to:
- Access unauthorized data.
- Modify or delete records.
- Escalate privileges or compromise the backend database.

- **Risk Level:** Critical  
- **CWE-ID:** [CWE-89 – SQL Injection](https://cwe.mitre.org/data/definitions/89.html)  
- **OWASP Category:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)  

---

## Affected URL & Parameters
| Vulnerability | URL Affected | Vulnerable Parameter |
|---------------|-------------|---------------------|
| SQL Injection | `http://testphp.vulnweb.com/listproducts.php?cat=1` | `cat` |

The `cat` parameter is directly used in backend SQL queries without input validation or parameterization.

---

## Proof of Concept (PoC)

### Steps:
1. **Access the Original Endpoint**  
   Visit:
3. **Analyze the Result**  
All products from all categories are displayed, confirming SQL logic bypass.

4. **Optional Automation**  
Use sqlmap to confirm and extract data:  

---

## Business Impact
SQL Injection vulnerabilities can lead to:
- **Data Breaches:** Exposure of sensitive information such as usernames, passwords, and financial records.
- **Regulatory Violations:** GDPR, HIPAA, or CCPA non-compliance.
- **Reputation Damage:** Loss of customer trust and potential financial penalties.
- **Operational Disruption:** Database corruption, unauthorized administrative actions, and pivoting into internal systems.

---

## Remediations & Recommendations
- **Parameterized Queries/Prepared Statements:** Treat user input strictly as data.
- **Input Validation:** Enforce allow-lists for input formats (e.g., numeric-only IDs).
- **Web Application Firewall (WAF):** Filter and block malicious payloads.
- **Least Privilege Principle:** Ensure the web app uses a restricted database account.
- **Error Handling:** Disable verbose error messages to prevent information leaks.
- **Secure SDLC Practices:** Regular code reviews, automated static analysis, and penetration testing.

---

## References
- [OWASP SQL Injection Cheat Sheet](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Top 10 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [NIST SP 800-115 – Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [CWE-89 – SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger Web Security Academy – SQL Injection Labs](https://portswigger.net/web-security/sql-injection)

---

## Disclaimer
This assessment was performed on a publicly available test environment designed for educational and training purposes.  
Do not use these techniques on unauthorized systems.

---

## Author
Prepared by **Mahesh (CSE – Cyber Security)**  
*(kairamkondamaheshh@gmail.com)*  

---

   The page displays products belonging to category 1.

2. **Inject a Malicious Payload**  
Modify the `cat` parameter with:  
Example:  

