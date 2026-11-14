# Cyber Bootcamp: Coursework & Assignments

> 🌐 **Live Interactive Infographic (GitHub Pages):** [https://Ammar-UT.github.io/C_Bootcamp/](https://Ammar-UT.github.io/C_Bootcamp/)  
> Visualizing the **Software Framework vs. Library** architectural research as a modern interactive Bento-grid infographic.

Welcome to my repository for the **Cyber Bootcamp**! This repository tracks my coursework, hands-on programming projects, security engineering tools, and technical research throughout the program.

---

## Table of Contents
1. [Overview](#overview)
2. [Branches](#branches)
3. [Assignments & Deliverables](#assignments--deliverables)
   - [1. Software Framework vs. Library (Research & Infographic)](#1-software-framework-vs-library)
   - [2. Password Strength Assessment CLI](#2-password-strength-assessment-cli)
   - [3. C-HexadecimalViewer (Hex Dump Utility)](#3-c-hexadecimalviewer-hex-dump-utility)
   - [4. C-LogFileParser (Log File Keyword Scanner)](#4-c-logfileparser-log-file-keyword-scanner)
   - [5. Multithreaded Port Scanner](#5-multithreaded-port-scanner)
   - [6. Banner Grabbing Tool](#6-banner-grabbing-tool)
   - [7. Automated Security Log Analyzer](#7-automated-security-log-analyzer)
   - [8. Password Generator & SHA-256 Hasher](#8-password-generator--sha-256-hasher)
   - [9. File Integrity Monitoring (FIM)](#9-file-integrity-monitoring-fim)
   - [10. HTTP Request Handler & REST API Tool](#10-http-request-handler--rest-api-tool)
   - [11. SQL Injection Defense Tool](#11-sql-injection-defense-tool)
   - [12. Secure File Upload System](#12-secure-file-upload-system)
   - [13. Session & Cookie Security Tool](#13-session--cookie-security-tool)
   - [14. DOM-Based XSS Prevention Tool](#14-dom-based-xss-prevention-tool)
4. [Repository Structure](#repository-structure)
5. [Getting Started](#getting-started)

---

## Overview
This repository documents practical work across systems programming in C, network security, incident detection and response, applied cryptography, web application security (PHP), and defensive frontend engineering studied in the Cyber Bootcamp.

---

## Branches

This repository is organized into distinct branches:

- **`main`**: Contains foundational lessons, exercises, and standard syllabus coursework.
- **`Assignments`**: Dedicated branch consolidating all standalone deliverables, in-depth technical reports, interactive demos, and assignment projects.

To switch to the `Assignments` branch:
```bash
git checkout Assignments
```

---

## Assignments & Deliverables

All assignments and projects are hosted on the [`Assignments`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments) branch under the [`Assignments/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments) directory.

### 1. Software Framework vs. Library
A deep-dive research paper and visual infographic exploring the architectural nuances between software frameworks and libraries, focusing on Inversion of Control (IoC).

- **Project Folder:** [`Assignments/Framework-vs-Library/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/Framework-vs-Library)
- **PDF Presentation:** [`Software Framework vs Library.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/Framework-vs-Library/Software%20Framework%20vs%20Library.pdf)
- **Interactive Bento Infographic:** [`framework-vs-library-bento.html`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/Framework-vs-Library/framework-vs-library-bento.html)
- **Summary Diagram:** [`framework-vs-library-2.jpg`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/Framework-vs-Library/framework-vs-library-2.jpg)
- **Live Demo:** [GitHub Pages Live App](https://Ammar-UT.github.io/C_Bootcamp/)
- **Key Concepts:** Inversion of Control (IoC), Hollywood Principle, extensibility, dependency management.

---

### 2. Password Strength Assessment CLI
A command-line security tool in C evaluating password robustness against standard complexity rules and providing granular remediation guidance.

- **Project Folder:** [`Assignments/PasswordStrengthChecker/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/PasswordStrengthChecker)
- **Source Code:** [`PasswordChecker.c`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/PasswordStrengthChecker/PasswordChecker.c)
- **Key Concepts:** Strings, loops, `<ctype.h>` classification (`isupper`, `islower`, `isdigit`, `ispunct`), conditional scoring.

---

### 3. C-HexadecimalViewer (Hex Dump Utility)
A low-level CLI binary inspector in C that prints raw file bytes in an 8-digit offset, 16-byte hex representation, and sanitized printable ASCII output.

- **Project Folder:** [`Assignments/C-HexadecimalViewer/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/C-HexadecimalViewer)
- **Source Code:** [`src/C-HexadecimalViewer.c`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/C-HexadecimalViewer/src/C-HexadecimalViewer.c)
- **Build Script:** [`makefile`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/C-HexadecimalViewer/makefile)
- **Technical Explanation Blog:** [`HEX_VIEWER_EXPLANATION.md`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/C-HexadecimalViewer/HEX_VIEWER_EXPLANATION.md)
- **Key Concepts:** Stream chunking via `fread()`, binary file handling (`"rb"`), safe ASCII filtering (`isprint()`), column padding, defensive error redirection to `stderr`.

---

### 4. C-LogFileParser (Log File Keyword Scanner)
A fast, memory-efficient command-line log analysis tool written in C that scans log files line by line, isolates security alerts by keyword (e.g., `Failed`, `ERROR`), and prints an audit report.

- **Project Folder:** [`Assignments/C-LogFileParser.c/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/C-LogFileParser.c)
- **Source Code:** [`src/C-LogFileParser.c`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/C-LogFileParser.c/src/C-LogFileParser.c)
- **Build Script:** [`makefile`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/C-LogFileParser.c/makefile)
- **Technical Explanation Blog:** [`LOG_FILE_PARSER_EXPLANATION.md`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/C-LogFileParser.c/LOG_FILE_PARSER_EXPLANATION.md)
- **Key Concepts:** Bounded streaming ingestion (`fgets`), fast substring matching (`strstr`), cross-platform newline stripping (`strcspn`), constant $O(1)$ memory footprint, defensive error handling (`perror`).

---

### 5. Multithreaded Port Scanner
A high-performance multithreaded network reconnaissance scanner written in Python that concurrently probes target IP ports using low-level TCP sockets to rapidly identify active services.

- **Project Folder:** [`Assignments/Python-MultiThread PortScanner/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/Python-MultiThread%20PortScanner)
- **Source Code:** [`Multithreaded-Port-Scanner.py`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/Python-MultiThread%20PortScanner/Multithreaded-Port-Scanner.py)
- **PDF Brief:** [`التكليف الخامس_ أداة فحص المنافذ متعددة الخيوط.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/Python-MultiThread%20PortScanner/%D8%A7%D9%84%D8%AA%D9%83%D9%84%D9%8A%D9%81%20%D8%A7%D9%84%D8%AE%D8%A7%D9%85%D8%B3_%20%D8%A3%D8%AF%D8%A7%D8%A9%20%D9%81%D8%AD%D8%B5%20%D8%A7%D9%84%D9%85%D9%86%D8%A7%D9%81%D8%B0%20%D9%85%D8%AA%D8%B9%D8%AF%D8%AF%D8%A9%20%D8%A7%D9%84%D8%AE%D9%8A%D9%88%D8%B7.pdf)
- **Key Concepts:** Low-level TCP sockets (`socket.socket`, `connect_ex`), concurrent execution via `concurrent.futures.ThreadPoolExecutor(max_workers=50)`, non-blocking timeout configuration, thread-safe console output with locks, execution timing.

---

### 6. Banner Grabbing Tool
A modular reconnaissance tool in Python designed to interact with open network ports, issue protocol-specific probes, and extract service identification banners to detect daemon versions and OS footprints.

- **Project Folder:** [`Assignments/BannerGrabbingTool/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/BannerGrabbingTool)
- **Source Code:** [`BannerGrabbingTool.py`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/BannerGrabbingTool/BannerGrabbingTool.py)
- **PDF Brief:** [`التكليف السادس_ أداة جلب بصمات الخدمات.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/BannerGrabbingTool/%D8%A7%D9%84%D8%AA%D9%83%D9%84%D9%8A%D9%81%20%D8%A7%D9%84%D8%B3%D8%A7%D8%AF%D8%B3_%20%D8%A3%D8%AF%D8%A7%D8%A9%20%D8%AC%D9%84%D8%A8%20%D8%A8%D8%B5%D9%85%D8%A7%D8%AA%20%D8%A7%D9%84%D8%AE%D8%AF%D9%85%D8%A7%D8%AA.pdf)
- **Key Concepts:** Socket stream negotiation (`socket.recv`), active protocol probing (HTTP `HEAD`/`GET` requests), passive vs. interactive service handling (SSH, FTP vs. HTTP), safe string sanitization and encoding handling.

---

### 7. Automated Security Log Analyzer
A SOC-oriented Python automation script that parses web server access logs line by line, compiles regular expressions to detect common web attack patterns, and produces structured security alert reports.

- **Project Folder:** [`Assignments/AutomatedLogAnalyzer/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/AutomatedLogAnalyzer)
- **Source Code:** [`AutomatedLogAnalyzer.py`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/AutomatedLogAnalyzer/AutomatedLogAnalyzer.py)
- **PDF Brief:** [`التكليف السابع_ أداة تحليل السجلات الأمنية.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/AutomatedLogAnalyzer/%D8%A7%D9%84%D8%AA%D9%83%D9%84%D9%8A%D9%81%20%D8%A7%D9%84%D8%B3%D8%A7%D8%A8%D8%B9_%20%D8%A3%D8%AF%D8%A7%D8%A9%20%D8%AA%D8%AD%D9%84%D9%8A%D9%84%20%D8%A7%D9%84%D8%B3%D8%AC%D9%84%D8%A7%D8%AA%20%D8%A7%D9%84%D8%A3%D9%85%D9%86%D9%8A%D8%A9.pdf)
- **Key Concepts:** Compiled regular expressions (`re.compile`), signature matching for SQL Injection, Path Traversal, Cross-Site Scripting (XSS), and Command Injection, incident telemetry and triage reporting.

---

### 8. Password Generator & SHA-256 Hasher
A dual-purpose security utility in Python providing cryptographically secure pseudo-random password generation along with cryptographic SHA-256 hashing to demonstrate irreversible digest generation and the avalanche effect.

- **Project Folder:** [`Assignments/PasswordGenerator&SHA-256 Hasher/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/PasswordGenerator%26SHA-256%20Hasher)
- **Source Code:** [`Password-Generator-SHA-256-Hasher.py`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/PasswordGenerator%26SHA-256%20Hasher/Password-Generator-SHA-256-Hasher.py)
- **PDF Brief:** [`التكليف الثامن_ مولد كلمات السر وحساب التجزئة.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/PasswordGenerator%26SHA-256%20Hasher/%D8%A7%D9%84%D8%AA%D9%83%D9%84%D9%8A%D9%81%20%D8%A7%D9%84%D8%AB%D8%A7%D9%85%D9%86_%20%D9%85%D9%88%D9%84%D8%AF%20%D9%83%D9%84%D9%85%D8%A7%D8%AA%20%D8%A7%D9%84%D8%B3%D8%B1%20%D9%88%D8%AD%D8%B3%D8%A7%D8%A8%20%D8%A7%D9%84%D8%AA%D8%AC%D8%B2%D8%A6%D8%A9.pdf)
- **Key Concepts:** Cryptographically Secure Pseudo-Random Number Generation (`secrets`), character pool entropy distribution, SHA-256 one-way hashing (`hashlib.sha256`), digest hex formatting, avalanche effect demonstration.

---

### 9. File Integrity Monitoring (FIM)
A lightweight host-based file integrity monitor written in Python that computes cryptographic baselines of critical files and continuously inspects them in real time to alert on unauthorized alterations or deletions.

- **Project Folder:** [`Assignments/File IntegrityMonitoring/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/File%20IntegrityMonitoring)
- **Source Code:** [`File-Integrity-Monitoring.py`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/File%20IntegrityMonitoring/File-Integrity-Monitoring.py)
- **PDF Brief:** [`التكليف التاسع_ أداة مراقبة سلامة الملفات.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/File%20IntegrityMonitoring/%D8%A7%D9%84%D8%AA%D9%83%D9%84%D9%8A%D9%81%20%D8%A7%D9%84%D8%AA%D8%A7%D8%B3%D8%B9_%20%D8%A3%D8%AF%D8%A7%D8%A9%20%D9%85%D8%B1%D8%A7%D9%82%D8%A8%D8%A9%20%D8%B3%D9%84%D8%A7%D9%85%D8%A9%20%D8%A7%D9%84%D9%85%D9%84%D9%81%D8%A7%D8%AA.pdf)
- **Key Concepts:** Chunked binary stream hashing (`hashlib`), baseline digest persistence, active polling loops, real-time file tampering detection, graceful handling of file removal and permission errors.

---

### 10. HTTP Request Handler & REST API Tool
A pure PHP RESTful API backend demonstrating standards-compliant request handling, HTTP method routing (GET, POST, PUT, DELETE), header inspection, JSON payload parsing, and appropriate HTTP response codes.

- **Project Folder:** [`Assignments/PHP-REST API/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/PHP-REST%20API)
- **Source Code:** [`index.php`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/PHP-REST%20API/index.php)
- **PDF Brief:** [`التكليف العاشر_ أداة معالجة طلبات HTTP وبناء REST API.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/PHP-REST%20API/%D8%A7%D9%84%D8%AA%D9%83%D9%84%D9%8A%D9%81%20%D8%A7%D9%84%D8%B9%D8%A7%D8%B4%D8%B1_%20%D8%A3%D8%AF%D8%A7%D8%A9%20%D9%85%D8%B9%D8%A7%D9%84%D8%AC%D8%A9%20%D8%B7%D9%84%D8%A8%D8%A7%D8%AA%20HTTP%20%D9%88%D8%A8%D9%86%D8%A7%D8%A1%20REST%20API.pdf)
- **Key Concepts:** RESTful routing via `$_SERVER['REQUEST_METHOD']`, reading raw JSON input from `php://input`, inspection of request headers (`getallheaders()`), status code compliance (200, 201, 400, 405), response serialization.

---

### 11. SQL Injection Defense Tool
A comparative PHP security tool demonstrating the vulnerability of raw dynamic SQL queries and contrasting them with robust defensive programming using PHP Data Objects (PDO) prepared statements.

- **Project Folder:** [`Assignments/SQLiDefense/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/SQLiDefense)
- **Source Code:** [`index.php`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/SQLiDefense/index.php)
- **PDF Brief:** [`التكليف الحادي عشر_ أداة الحماية من ثغرات SQL Injection.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/SQLiDefense/%D8%A7%D9%84%D8%AA%D9%83%D9%84%D9%8A%D9%81%20%D8%A7%D9%84%D8%AD%D8%A7%D8%AF%D9%8A%20%D8%B9%D8%B4%D8%B1_%20%D8%A3%D8%AF%D8%A7%D8%A9%20%D8%A7%D9%84%D8%AD%D9%85%D8%A7%D9%8A%D8%A9%20%D9%85%D9%86%20%D8%AB%D8%BA%D8%B1%D8%A7%D8%AA%20SQL%20Injection.pdf)
- **Key Concepts:** In-memory SQLite via PDO, parameterized queries with `prepare()` and `bindValue()`, prevention of authentication bypass attacks (`' OR '1'='1`), safe exception management (`PDO::ERRMODE_EXCEPTION`).

---

### 12. Secure File Upload System
A defense-in-depth file upload system in PHP enforcing comprehensive multi-layer validation to eliminate arbitrary file upload vulnerabilities, remote code execution (RCE), and path traversal.

- **Project Folder:** [`Assignments/PHP-FileUpload/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/PHP-FileUpload)
- **Source Code:** [`index.php`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/PHP-FileUpload/index.php)
- **Security Config:** [`uploads/.htaccess`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/PHP-FileUpload/uploads/.htaccess)
- **PDF Brief:** [`التكليف الثاني عشر_ نظام رفع الملفات الآمن.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/PHP-FileUpload/%D8%A7%D9%84%D8%AA%D9%83%D9%84%D9%8A%D9%81%20%D8%A7%D9%84%D8%AB%D8%A7%D9%86%D9%8A%20%D8%B9%D8%B4%D8%B1_%20%D9%86%D8%B8%D8%A7%D9%85%20%D8%B1%D9%81%D8%B9%20%D8%A7%D9%84%D9%85%D9%84%D9%81%D8%A7%D8%AA%20%D8%A7%D9%84%D8%A2%D9%85%D9%86.pdf)
- **Key Concepts:** Multi-tier verification: upload error validation, file size limits (2MB), strict extension whitelist, genuine MIME validation via `finfo_file()`, cryptographic filename obfuscation (`bin2hex(random_bytes(16))`), `.htaccess` script execution prevention.

---

### 13. Session & Cookie Security Tool
A session hardening utility and web interface in PHP illustrating how to safeguard session cookies against Session Hijacking (XSS) and Session Fixation attacks through proper flag configuration.

- **Project Folder:** [`Assignments/Session &Cookie Security/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/Session%20%26Cookie%20Security)
- **Source Code:** [`index.php`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/Session%20%26Cookie%20Security/index.php)
- **PDF Brief:** [`التكليف الثالث عشر_ أداة إدارة الجلسات والكوكيز الآمنة.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/Session%20%26Cookie%20Security/%D8%A7%D9%84%D8%AA%D9%83%D9%84%D9%8A%D9%81%20%D8%A7%D9%84%D8%AB%D8%A7%D9%84%D8%AB%20%D8%B9%D8%B4%D8%B1_%20%D8%A3%D8%AF%D8%A7%D8%A9%20%D8%A5%D8%AF%D8%A7%D8%B1%D8%A9%20%D8%A7%D9%84%D8%AC%D9%84%D8%B3%D8%A7%D8%AA%20%D9%88%D8%A7%D9%84%D9%83%D9%88%D9%83%D9%8A%D8%B2%20%D8%A7%D9%84%D8%A2%D9%85%D9%86%D8%A9.pdf)
- **Key Concepts:** `session_set_cookie_params()` with security flags, `HttpOnly` cookie enforcement against JavaScript access, `SameSite=Strict` CSRF mitigation, session ID regeneration via `session_regenerate_id(true)` upon privilege changes.

---

### 14. DOM-Based XSS Prevention Tool
An interactive client-side web application built with vanilla JavaScript, HTML5, and CSS3 providing a visual, side-by-side comparison between insecure DOM sinks (`innerHTML`) and secure rendering methods (`textContent`).

- **Project Folder:** [`Assignments/DOM-XSS/`](https://github.com/Ammar-UT/C_Bootcamp/tree/Assignments/Assignments/DOM-XSS)
- **Source Code:** [`app.js`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/DOM-XSS/app.js), [`index.html`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/DOM-XSS/index.html), [`style.css`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/DOM-XSS/style.css)
- **PDF Brief:** [`التكليف الرابع عشر_ أداة التفاعل مع DOM والوقاية من ثغرات XSS.pdf`](https://github.com/Ammar-UT/C_Bootcamp/blob/Assignments/Assignments/DOM-XSS/%D8%A7%D9%84%D8%AA%D9%83%D9%84%D9%8A%D9%81%20%D8%A7%D9%84%D8%B1%D8%A7%D8%A8%D8%B9%20%D8%B9%D8%B4%D8%B1_%20%D8%A3%D8%AF%D8%A7%D8%A9%20%D8%A7%D9%84%D8%AA%D9%81%D8%A7%D8%B9%D9%84%20%D9%85%D8%B9%20DOM%20%D9%88%D8%A7%D9%84%D9%88%D9%82%D8%A7%D9%8A%D8%A9%20%D9%85%D9%86%20%D8%AB%D8%BA%D8%B1%D8%A7%D8%AA%20XSS.pdf)
- **Key Concepts:** DOM manipulation, dangerous sink vulnerability analysis (`innerHTML`), safe sink enforcement (`textContent`), browser-side contextual sanitization, interactive payload testing.

---

## Repository Structure

```text
.
├── Assignments/
│   ├── AutomatedLogAnalyzer/                # Security log parsing with Regex (Python)
│   │   ├── AutomatedLogAnalyzer.py
│   │   └── التكليف السابع_ أداة تحليل السجلات الأمنية.pdf
│   ├── BannerGrabbingTool/                  # Active service banner grabber (Python)
│   │   ├── BannerGrabbingTool.py
│   │   └── التكليف السادس_ أداة جلب بصمات الخدمات.pdf
│   ├── C-HexadecimalViewer/                 # Low-level binary inspector (C)
│   │   ├── HEX_VIEWER_EXPLANATION.md
│   │   ├── makefile
│   │   └── src/
│   │       └── C-HexadecimalViewer.c
│   ├── C-LogFileParser.c/                   # Keyword log scanner (C)
│   │   ├── LOG_FILE_PARSER_EXPLANATION.md
│   │   ├── makefile
│   │   └── src/
│   │       └── C-LogFileParser.c
│   ├── DOM-XSS/                             # DOM XSS demonstration & mitigation (JS/HTML/CSS)
│   │   ├── app.js
│   │   ├── index.html
│   │   ├── style.css
│   │   └── التكليف الرابع عشر_ أداة التفاعل مع DOM والوقاية من ثغرات XSS.pdf
│   ├── File IntegrityMonitoring/            # Real-time file integrity monitor (Python)
│   │   ├── File-Integrity-Monitoring.py
│   │   └── التكليف التاسع_ أداة مراقبة سلامة الملفات.pdf
│   ├── Framework-vs-Library/                # Architecture research & interactive Bento grid
│   │   ├── Software Framework vs Library.pdf
│   │   ├── framework-vs-library-2.jpg
│   │   └── framework-vs-library-bento.html
│   ├── PasswordGenerator&SHA-256 Hasher/    # CSPRNG generator & SHA-256 hasher (Python)
│   │   ├── Password-Generator-SHA-256-Hasher.py
│   │   └── التكليف الثامن_ مولد كلمات السر وحساب التجزئة.pdf
│   ├── PasswordStrengthChecker/             # Password complexity validator (C)
│   │   └── PasswordChecker.c
│   ├── PHP-FileUpload/                      # Multi-layer secure file upload system (PHP)
│   │   ├── index.php
│   │   ├── uploads/
│   │   │   └── .htaccess
│   │   └── التكليف الثاني عشر_ نظام رفع الملفات الآمن.pdf
│   ├── PHP-REST API/                        # RESTful HTTP request router & API (PHP)
│   │   ├── index.php
│   │   └── التكليف العاشر_ أداة معالجة طلبات HTTP وبناء REST API.pdf
│   ├── Python-MultiThread PortScanner/      # Multithreaded TCP port scanner (Python)
│   │   ├── Multithreaded-Port-Scanner.py
│   │   └── التكليف الخامس_ أداة فحص المنافذ متعددة الخيوط.pdf
│   ├── Session &Cookie Security/            # Session security & cookie flags hardening (PHP)
│   │   ├── index.php
│   │   └── التكليف الثالث عشر_ أداة إدارة الجلسات والكوكيز الآمنة.pdf
│   └── SQLiDefense/                         # SQL injection defense with PDO (PHP)
│       ├── index.php
│       └── التكليف الحادي عشر_ أداة الحماية من ثغرات SQL Injection.pdf
├── C Programming/                           # Coursework and lesson practice
├── Python Programming/                      # Python exercises and scripts
├── docs/                                    # GitHub Pages deployment site
├── .gitignore                               # Whitelist configuration
└── README.md                                # Root documentation
```

---

## Getting Started

### Systems Programming in C

#### Hexadecimal Viewer:
```bash
cd "Assignments/C-HexadecimalViewer"
make
./bin/c-hexdump makefile
```

#### Password Strength Checker:
```bash
cd "Assignments/PasswordStrengthChecker"
gcc -o passchecker PasswordChecker.c
./passchecker
```

#### Log File Parser:
```bash
cd "Assignments/C-LogFileParser.c"
make
./bin/logparser /var/log/auth.log Failed
```

---

### Python Security Utilities

#### Multithreaded Port Scanner:
```bash
cd "Assignments/Python-MultiThread PortScanner"
python3 Multithreaded-Port-Scanner.py 127.0.0.1 1 1024
```

#### Banner Grabbing Tool:
```bash
cd "Assignments/BannerGrabbingTool"
python3 BannerGrabbingTool.py 127.0.0.1 -p 22 80 8080
```

#### Automated Security Log Analyzer:
```bash
cd "Assignments/AutomatedLogAnalyzer"
python3 AutomatedLogAnalyzer.py /var/log/nginx/access.log
```

#### Password Generator & SHA-256 Hasher:
```bash
cd "Assignments/PasswordGenerator&SHA-256 Hasher"
python3 Password-Generator-SHA-256-Hasher.py --generate -l 16
python3 Password-Generator-SHA-256-Hasher.py --hash "MySecretPassword"
```

#### File Integrity Monitoring (FIM):
```bash
cd "Assignments/File IntegrityMonitoring"
python3 File-Integrity-Monitoring.py /etc/hosts
```

---

### PHP & Web Security Backends

Run any PHP assignment using the built-in development web server:

```bash
# REST API:
cd "Assignments/PHP-REST API" && php -S localhost:8000

# SQL Injection Defense:
cd "Assignments/SQLiDefense" && php -S localhost:8000

# Secure File Upload:
cd "Assignments/PHP-FileUpload" && php -S localhost:8000

# Session & Cookie Security:
cd "Assignments/Session &Cookie Security" && php -S localhost:8000
```

---

### Frontend & DOM Security

Open the interactive DOM-XSS demonstration directly in any browser:
```bash
cd "Assignments/DOM-XSS"
xdg-open index.html   # Linux
# Or run via local server:
python3 -m http.server 8080
```
