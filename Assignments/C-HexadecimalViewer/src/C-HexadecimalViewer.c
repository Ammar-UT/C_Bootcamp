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
                printf("   ");
            }

            if (i == 7) {
                printf(" ");
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
