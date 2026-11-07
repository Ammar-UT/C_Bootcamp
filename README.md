# Cyber Bootcamp: Coursework & Assignments

> 🌐 **Live Interactive Infographic (GitHub Pages):** [https://Ammar-UT.github.io/C_Bootcamp/](https://Ammar-UT.github.io/C_Bootcamp/)  
> Visualizing the **Software Framework vs. Library** architectural research as a modern interactive Bento-grid infographic.

Welcome to my repository for the **Cyber Bootcamp**! This repository tracks my coursework, hands-on programming projects, assignments, and technical research throughout the program.

---

## Table of Contents
1. [Overview](#overview)
2. [Branches](#branches)
3. [Assignments & Deliverables](#assignments--deliverables)
   - [1. Software Framework vs. Library (Research & Infographic)](#1-software-framework-vs-library)
   - [2. Password Strength Assessment CLI](#2-password-strength-assessment-cli)
   - [3. C-HexadecimalViewer (Hex Dump Utility)](#3-c-hexadecimalviewer-hex-dump-utility)
4. [Repository Structure](#repository-structure)
5. [Getting Started](#getting-started)

---

## Overview
This repository documents practical work across systems programming in C, security practices, and core software engineering concepts studied in the Cyber Bootcamp.

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

## Repository Structure

```text
.
├── Assignments/
│   ├── C-HexadecimalViewer/                 # Hexadecimal inspector project
│   │   ├── HEX_VIEWER_EXPLANATION.md        # Complete implementation blog
│   │   ├── makefile                         # Build automation
│   │   └── src/
│   │       └── C-HexadecimalViewer.c        # Hex dump source code
│   ├── Framework-vs-Library/                # Research and visual presentation
│   │   ├── Software Framework vs Library.pdf
│   │   ├── framework-vs-library-2.jpg
│   │   └── framework-vs-library-bento.html
│   └── PasswordStrengthChecker/             # Password complexity validator
│       └── PasswordChecker.c
├── C Programming/                           # Coursework and lesson practice
├── Python Programming/                      # Python exercises and scripts
├── docs/                                    # GitHub Pages deployment site
├── .gitignore                               # Whitelist configuration
└── README.md                                # Root documentation
```

---

## Getting Started

### Building & Running Assignments

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
