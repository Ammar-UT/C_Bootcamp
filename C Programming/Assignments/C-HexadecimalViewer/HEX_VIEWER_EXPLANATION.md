# Building a Fast Hexadecimal File Viewer (Hex Dump) in C

When analyzing compiled binaries, reverse-engineering malware, or debugging low-level file formats, text editors fall short because raw binary files contain non-printable bytes, control codes, and null bytes (`0x00`). 

A **Hex Dump** (or Hexadecimal Viewer) provides a low-level, byte-by-byte visual representation of any file. In this guide, we break down how to implement a clean CLI hex dump tool in C—similar to the standard Unix `hexdump -C` or `xxd` utilities.

---

## 1. Architectural Overview & Output Format

Standard hex viewers align data into a 3-column format:
1. **Offset:** Memory address or byte position from the beginning of the file (in 8-digit hexadecimal, e.g. `00000010`).
2. **Hex View:** 16 bytes per line shown in 2-digit uppercase hexadecimal (`%02X`), grouped with an extra space in the center for human readability.
3. **ASCII View:** Printable representation of each byte (`isprint()`), replacing non-printable control characters with a dot (`.`).

### Example Output
```text
Offset    Hexadecimal                                       ASCII
--------  ------------------------------------------------  ----------------
00000000  62 69 6E 61 72 79 3A 0A  09 40 6D 6B 64 69 72 20  binary:..@mkdir 
00000010  2D 70 20 62 69 6E 0A 09  40 67 63 63 20 2D 6F 20  -p bin..@gcc -o 
00000020  62 69 6E 2F 63 2D 68 65  78 64 75 6D 70 20 73 72  bin/c-hexdump sr
00000030  63 2F 43 2D 48 65 78 61  64 65 63 69 6D 61 6C 56  c/C-HexadecimalV
00000040  69 65 77 65 72 2E 63                              iewer.c
```

---

## 2. Complete Source Code

Here is the full implementation from [`C-HexadecimalViewer.c`](file:///home/d1337/Documents/Programming/CyberBootcamp/C%20Programming/Assignments/C-HexadecimalViewer/src/C-HexadecimalViewer.c):

```c
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#define BYTES_PER_LINE 16

void print_hex_editor(FILE *file) {
    unsigned char buffer[BYTES_PER_LINE];
    size_t offset = 0;
    size_t bytes_read;

    // Header
    printf("Offset    Hexadecimal                                       ASCII\n");
    printf("--------  ------------------------------------------------  ----------------\n");

    while ((bytes_read = fread(buffer, 1, BYTES_PER_LINE, file)) > 0) {
        // Print 8-digit hexadecimal offset
        printf("%08lx  ", (unsigned long)offset);

        // Print hex values (with an extra spacing after 8 bytes)
        for (size_t i = 0; i < BYTES_PER_LINE; i++) {
            if (i < bytes_read) {
                printf("%02X ", buffer[i]);
            } else {
                printf("   "); // 3 spaces to preserve column alignment for short/last lines
            }

            if (i == 7) {
                printf(" "); // Center column divider
            }
        }

        printf(" ");

        // Print ASCII representation
        for (size_t i = 0; i < bytes_read; i++) {
            if (isprint(buffer[i])) {
                printf("%c", buffer[i]);
            } else {
                printf(".");
            }
        }

        printf("\n");
        offset += bytes_read;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        fprintf(stderr, "Example: %s document.bin\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
        return 1;
    }

    print_hex_editor(file);

    fclose(file);
    return 0;
}
```

---

## 3. Deep Dive into Implementation Details

### A. Binary Mode File Access (`"rb"`)
```c
FILE *file = fopen(filename, "rb");
```
When inspecting arbitrary files, opening with `"r"` in text mode can cause issues on some platforms (e.g. carriage-return translation `\r\n` $\leftrightarrow$ `\n` or premature EOF on `0x1A` under Windows). Using `"rb"` guarantees that the operating system returns raw, untransformed bytes.

### B. Buffered Block Reading with `fread`
```c
while ((bytes_read = fread(buffer, 1, BYTES_PER_LINE, file)) > 0)
```
- Rather than reading byte-by-byte (`fgetc`), we read chunks of 16 bytes directly into `unsigned char buffer[BYTES_PER_LINE]`.
- Using `unsigned char` is essential: in C, plain `char` may be signed on many architectures, leading to sign extension errors when casting or printing hexadecimal values.
- `fread()` returns the actual number of elements read. The final line of a file often contains fewer than 16 bytes.

### C. Column Alignment for Incomplete Lines
Notice the `else` branch in the hex rendering loop:
```c
if (i < bytes_read) {
    printf("%02X ", buffer[i]);
} else {
    printf("   ");
}
```
If the file size is not a clean multiple of 16, the last line will contain trailing empty slots. Printing 3 spaces (`"   "`) per missing byte ensures that the ASCII column remains vertically aligned with preceding lines.

### D. Safe Character Filtering with `<ctype.h>`
```c
if (isprint(buffer[i])) {
    printf("%c", buffer[i]);
} else {
    printf(".");
}
```
`isprint()` checks if a byte corresponds to a printable ASCII character (values from `0x20` space to `0x7E` tilde `~`). Non-printable characters (such as null bytes, bell `\a`, backspaces, or escape codes) are safely rendered as a dot (`.`), preventing terminal corruption.

---

## 4. Compilation & Usage

The project includes a `makefile` to build the binary cleanly:

```bash
# Build the binary
make

# Run against any binary or text file
./bin/c-hexdump makefile
./bin/c-hexdump /bin/ls
```

---

## 5. Key Takeaways
- **Stream vs. Block Processing:** Reading fixed-width chunks minimizes system call overhead while keeping memory usage constant ($O(1)$ RAM footprint regardless of file size).
- **Format Specifiers:** `%08lx` produces padded hex offsets, and `%02X` guarantees uniform two-character byte representations.
- **Defensive Error Handling:** Directing diagnostic and usage errors to `stderr` keeps standard output pure for Unix pipe redirection (e.g. `./c-hexdump file.bin | grep "41 42"`).

