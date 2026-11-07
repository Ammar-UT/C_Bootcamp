# Building a High-Performance Log File Parser in C

In cybersecurity operations, system administration, and incident response, logs are the primary ground truth. Security Information and Event Management (SIEM) engines, intrusion detection systems (IDS), and firewalls produce millions of log entries daily. While high-level scripting languages like Python or bash pipelines (`grep | awk`) are popular, parsing massive multi-gigabyte log files at line rate often demands the low-level efficiency, predictable memory overhead, and speed of C.

In this guide, we break down how to design and build a robust, command-line **Log File Parser** in C that inspects unstructured log streams, isolates security indicators (e.g., `ERROR`, `FAILED`, `CRITICAL`), tracks precise line offsets, and produces a structured audit summary.

---

## 1. Architectural Design & Workflow

A resilient CLI log analyzer follows a single-pass streaming model:

```
[ Log File on Disk ] 
        │
        ▼ (fopen "r")
 [ Stream Ingestion ]  ───► Reads fixed-size buffer line-by-line (fgets)
        │
        ▼ (strstr)
 [ Keyword Matcher  ]  ───► Checks for security alert pattern / keyword
        │
   ┌────┴──────────────────────────┐
   ▼ (Match found)                 ▼ (No match)
[ Format & Emit Alert ]     [ Advance Line Counter ]
   │                               │
   └─────────────┬─────────────────┘
                 ▼
         [ Repeat till EOF ]
                 │
                 ▼
      [ Audit Report Summary ]
```

### Key Technical Goals:
1. **Bounded Memory Footprint ($O(1)$ RAM):** Avoid loading entire gigabyte-scale log files into memory; stream line-by-line through a dedicated buffer.
2. **Deterministic String Search:** Detect substring patterns without complex regex overhead using standard string manipulation routines (`strstr`).
3. **Clean Terminal Output:** Sanitize dynamic CRLF/LF line endings using `strcspn` before rendering alerts.
4. **Defensive Error Handling:** Validate CLI argument count and file descriptors with POSIX diagnostic reporting (`perror`).

---

## 2. Complete Source Code

Here is the implementation from [`src/C-LogFileParser.c`](file:///home/d1337/Documents/Programming/CyberBootcamp/Assignments/C-LogFileParser.c/src/C-LogFileParser.c):

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 512

int main(int argc, char *argv[]) {
    // 1. Verify command-line arguments
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <log_file> <keyword>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *keyword = argv[2];

    // 2. Open the log file in read-only text mode
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    char line[BUFFER_SIZE];
    int line_number = 0;
    int alert_count = 0;

    printf("=== Scanning: %s for '%s' ===\n\n", filename, keyword);

    // 3. Read line by line until EOF
    while (fgets(line, sizeof(line), file) != NULL) {
        line_number++;

        // 4. Check for keyword presence
        if (strstr(line, keyword) != NULL) {
            alert_count++;

            // Strip trailing newlines for clean console formatting
            line[strcspn(line, "\r\n")] = '\0';

            // Print matching alert with line number
            printf("[Alert #%d] Line %d: %s\n", alert_count, line_number, line);
        }
    }

    // 5. Clean up open file descriptors
    fclose(file);

    // 6. Display audit summary
    printf("\n=========================================\n");
    printf("Total lines scanned : %d\n", line_number);
    printf("Total alerts found  : %d\n", alert_count);
    printf("=========================================\n");

    return 0;
}
```

---

## 3. Deep Dive into Implementation Details

### A. Defensive Argument Validation & Error Redirection
```c
if (argc < 3) {
    fprintf(stderr, "Usage: %s <log_file> <keyword>\n", argv[0]);
    return 1;
}
```
In Unix tooling, error messages must never be written to `stdout`. Writing errors to `stderr` allows operators to cleanly chain the parser with downstream tools (such as piping stdout to a report file or pager: `./logparser auth.log FAILED > report.txt`) without polluting the output with error traces.

### B. Safe Streaming Ingestion with `fgets()`
```c
char line[BUFFER_SIZE];
while (fgets(line, sizeof(line), file) != NULL)
```
- **Why not `fscanf` or `gets`?** The historical `gets()` function does not check bounds and is notoriously vulnerable to buffer overflows. `fscanf("%s")` splits on whitespace rather than line boundaries.
- `fgets()` reads up to `sizeof(line) - 1` bytes and automatically appends a null terminator (`\0`), guaranteeing memory safety.
- It returns `NULL` upon reaching the end of the file (`EOF`) or encountering a read error, cleanly terminating the streaming loop.

### C. Substring Matching via `strstr()`
```c
if (strstr(line, keyword) != NULL)
```
- `<string.h>` provides `strstr(haystack, needle)`, which locates the first occurrence of `keyword` inside `line`.
- If the keyword exists anywhere in the line, `strstr` returns a pointer to the start of the substring; if absent, it returns `NULL`.
- Because this relies on fast byte comparisons without regular expression engine compilation overhead, it executes in nanoseconds per line.

### D. Sanitizing Platform-Dependent Newlines with `strcspn()`
```c
line[strcspn(line, "\r\n")] = '\0';
```
Logs exported from different operating systems mix newline formats:
- Linux / Unix: `\n` (LF)
- Windows / Network protocols: `\r\n` (CRLF)

`fgets()` retains the trailing newline character in the buffer. If left untreated, printing `printf("%s\n", line)` would produce double spacing or corrupt carriage returns. 

`strcspn(line, "\r\n")` computes the length of the initial segment of `line` that does not contain `\r` or `\n`. Setting `line[strcspn(...)] = '\0'` cleanly truncates either newline variant in a single operation.

---

## 4. Build System & Compilation

The project uses a clean `makefile` targeting GCC with strict warning flags (`-Wall`) and debug symbols (`-g`):

```makefile
binary:
	@mkdir -p bin
	@gcc -o bin/logparser src/C-LogFileParser.c -Wall -g
```

To build:
```bash
make
```

The resulting executable is generated in [`bin/logparser`](file:///home/d1337/Documents/Programming/CyberBootcamp/Assignments/C-LogFileParser.c/bin/logparser).

---

## 5. Practical Example & Execution

### Sample Log File (`sample_auth.log`)
```text
Nov 07 08:00:12 server-01 sshd[1024]: Accepted publickey for admin from 192.168.1.50 port 54222
Nov 07 08:01:45 server-01 sshd[1050]: Failed password for invalid user root from 203.0.113.42 port 39120
Nov 07 08:01:48 server-01 sshd[1052]: Failed password for invalid user admin from 203.0.113.42 port 39122
Nov 07 08:02:10 server-01 sudo[1060]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update
Nov 07 08:02:30 server-01 sshd[1065]: Failed password for invalid user test from 203.0.113.42 port 39126
```

### Running the Parser
```bash
./bin/logparser sample_auth.log Failed
```

### Output:
```text
=== Scanning: sample_auth.log for 'Failed' ===

[Alert #1] Line 2: Nov 07 08:01:45 server-01 sshd[1050]: Failed password for invalid user root from 203.0.113.42 port 39120
[Alert #2] Line 3: Nov 07 08:01:48 server-01 sshd[1052]: Failed password for invalid user admin from 203.0.113.42 port 39122
[Alert #3] Line 5: Nov 07 08:02:30 server-01 sshd[1065]: Failed password for invalid user test from 203.0.113.42 port 39126

=========================================
Total lines scanned : 5
Total alerts found  : 3
=========================================
```

---

## 6. Key Takeaways & Security Engineering Lessons

1. **Streaming Minimizes Vulnerability Surface:** Keeping buffers fixed (`BUFFER_SIZE 512`) and bounded by `sizeof(line)` protects system analyzers against Out-Of-Memory (OOM) denial-of-service attacks from malicious log bombs.
2. **Cross-Platform String Hygiene:** Handling `\r\n` safely prevents terminal manipulation attacks (e.g. carriage-return overwrites where attackers forge log visual output).
3. **Auditing & Forensic Readiness:** Tracking exact source line numbers accelerates timeline reconstruction during security investigations.

