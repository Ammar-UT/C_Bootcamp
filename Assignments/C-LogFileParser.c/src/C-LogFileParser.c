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