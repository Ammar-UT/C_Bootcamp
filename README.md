# Cyber Bootcamp: C Programming

Welcome to my C programming repository for the **Cyber Bootcamp**! This repository tracks my journey learning C for cybersecurity and systems programming.

---

## Assignment 1: Password Strength Checker

- **Location:** `C Programming/Lesson 02/PasswordChecker.c`
- **Topic:** Arrays, Strings, Loops, and Character Classification (`<ctype.h>`)

### 📖 Overview
The **Password Strength Checker** is a CLI tool developed in C that assesses the strength of a user-provided password based on standard security requirements. It calculates an overall score and provides immediate feedback on what criteria need improvement.

---

### 🛡️ Password Criteria
To achieve a high security score, passwords are evaluated against five fundamental rules:

| Requirement | Description | Check |
| :--- | :--- | :--- |
| **Length** | At least 8 characters long | Character count $\ge$ 8 |
| **Uppercase** | Contains uppercase letters (`A-Z`) | `isupper()` |
| **Lowercase** | Contains lowercase letters (`a-z`) | `islower()` |
| **Numbers** | Contains numerical digits (`0-9`) | `isdigit()` |
| **Symbols** | Contains special characters (`!`, `@`, `#`, etc.) | `ispunct()` |

---

### Scoring & Strength Levels

| Score | Rating |
| :---: | :--- |
| **5** | **Very Strong** |
| **4** | **Strong** |
| **3** | **Medium** |
| **2** | **Weak** |
| **0 - 1** | **Very Weak** |

If any requirements are missing, the program outputs specific suggestions under **Password Checker Details**.

---

### Getting Started

#### 1. Compile
Navigate to `C Programming/Lesson 02` and compile with `gcc`:

```bash
cd "C Programming/Lesson 02"
gcc -o passchecker PasswordChecker.c
```

#### 2. Run
Execute the compiled binary:

```bash
./passchecker
```

---

### Example Output

```text
Note Password must contains: 
 -Uppercase, 
 -Lowercase, 
 -Numbers, 
 -Symbols
-------------------------------------------------
Enter your password: pasdasdk3433

---------- Password Strength --------------------
Password is Medium
Score: 3

---------- Password Checker Details -------------
Password needs an uppercase letter
Password needs a symbol
```

---

### Concepts Learned
- Declaring and manipulating **character arrays** (strings) in C.
- Working with the null-terminator byte (`'\0'`).
- Using character inspection functions from `<ctype.h>` (`isupper`, `islower`, `isdigit`, `ispunct`).
- Accumulating scores and branching with conditional logic (`if`, `else if`, `else`).
- Building interactive command-line interfaces with `printf` and `scanf`.
