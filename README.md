# Cyber Bootcamp: C Programming & Assignments

Welcome to my repository for the **Cyber Bootcamp**! This repository tracks my coursework, coding projects, and technical research throughout the program.

---

## Table of Contents
1. [Overview](#overview)
2. [Assignments & Research](#assignments--research)
   - [Assignment: Software Framework vs. Library](#assignment-software-framework-vs-library)
   - [Assignment: Password Strength Checker](#assignment-password-strength-checker)
3. [Repository Structure](#repository-structure)
4. [Getting Started](#getting-started)

---

## Overview
This repository documents practical work across systems programming in C, security practices, and core software engineering concepts studied in the Cyber Bootcamp.

---

## Assignments & Research

### Assignment: Software Framework vs. Library
- **Location:** [`Assignments/Software Framework vs Library.pdf`](file:///home/d1337/Documents/Programming/CyberBootcamp/Assignments/Software%20Framework%20vs%20Library.pdf)
- **Author:** Ammar Alabsee
- **Date:** 2 Nov 2026

#### Executive Summary
Understanding the distinction between a **framework** and a **library** is essential during development. While many simplify the concept as *"a framework is a collection of libraries"*, the core architectural difference lies in the **Inversion of Control (IoC)** — *"Who calls whom"*:
- **Library:** Your application code calls the library functions to perform specific, isolated tasks. You maintain control over application flow.
- **Framework:** The framework dictates the architecture and control flow, invoking your custom code at predefined extension points.

#### Key Comparison Matrix

| Evaluation Category | Framework | Library |
| :--- | :--- | :--- |
| **Core Concept / Focus** | Complete application structure comprising APIs, compilers, support tools, and conventions. | Targeted collection of helper modules, classes, and pre-written functions. |
| **Control Flow** | Framework calls user code (*Inversion of Control*). | User code calls the library. |
| **Flexibility & Swappability** | High architectural lock-in; difficult to swap or replace once chosen. | High flexibility; easy to replace with alternative packages. |
| **Performance & Footprint** | Heavier footprint, larger abstraction overhead, structured boilerplate. | Lightweight, minimal overhead, pay only for what you import. |
| **Integration** | Best suited to scaffold new applications from the start. | Integrates effortlessly into existing codebases to add specific features. |
| **Common Examples** | Next.js, Django, Laravel, Gin, PyTorch | React, Axios, Pandas, Redux, jQuery |

#### When to Use Which
- **Choose a Framework when:** Building complex, multi-route applications needing standardized routing, state management, security scaffolding, or enterprise architectural consistency across teams.
- **Choose a Library when:** Solving a specific, targeted challenge (e.g., HTTP requests, data manipulation) or when lightweight execution and full architectural flexibility are critical.

---

### Assignment: Password Strength Checker
- **Location:** [`C Programming/Lesson 02/PasswordChecker.c`](file:///home/d1337/Documents/Programming/CyberBootcamp/C%20Programming/Lesson%2002/PasswordChecker.c)
- **Topic:** Arrays, Strings, Loops, and Character Classification (`<ctype.h>`)

#### Overview
A CLI security tool developed in C that evaluates password robustness against 5 foundational criteria and provides immediate remediation feedback.

#### Password Evaluation Rules

| Requirement | Description | Check |
| :--- | :--- | :--- |
| **Length** | At least 8 characters long | Character count $\ge$ 8 |
| **Uppercase** | Contains uppercase letters (`A-Z`) | `isupper()` |
| **Lowercase** | Contains lowercase letters (`a-z`) | `islower()` |
| **Numbers** | Contains numerical digits (`0-9`) | `isdigit()` |
| **Symbols** | Contains special characters (`!`, `@`, `#`, etc.) | `ispunct()` |

#### Scoring Levels

| Score | Rating |
| :---: | :--- |
| **5** | **Very Strong** |
| **4** | **Strong** |
| **3** | **Medium** |
| **2** | **Weak** |
| **0 - 1** | **Very Weak** |

---

## Repository Structure

```text
.
├── Assignments/
│   ├── Software Framework vs Library.pdf    # Research & presentation on Framework vs. Library
│   └── framework-vs-library.jpg             # Summary visual diagram
├── C Programming/
│   └── Lesson 02/
│       ├── PasswordChecker.c                # Password strength assessment source code
│       └── passchecker                      # Compiled binary
├── .gitignore                               # Whitelist configuration
└── README.md                                # Project documentation
```

---

## Getting Started

### Compiling & Running C Programs

Navigate to the lesson directory and compile using `gcc`:

```bash
cd "C Programming/Lesson 02"
gcc -o passchecker PasswordChecker.c
./passchecker
```

### Viewing PDF Assignments

The research documentation is available directly in the [`Assignments/`](file:///home/d1337/Documents/Programming/CyberBootcamp/Assignments) directory:
- [Software Framework vs Library.pdf](file:///home/d1337/Documents/Programming/CyberBootcamp/Assignments/Software%20Framework%20vs%20Library.pdf)
