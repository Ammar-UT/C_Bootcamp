#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main() {

    char password[100];
    int length = 0;
    int uppercase = 0;
    int lowercase = 0;
    int digit = 0;
    int symbol = 0;
    int score = 0;

    printf("\nNote Password must contains: \n -Uppercase, \n -Lowercase, \n -Numbers, \n -Symbols\n");
    printf("-------------------------------------------------");
    printf("\nEnter your password: ");
    scanf("%s", password);

    for (int i = 0; i < 100; i++) {
        if (password[i] == '\0') {
            length = i;
            break;
        }
    }

    if (length >= 8) {
        score += 1;
    } else {
        printf("\n-------------------------------------------------\n");
        printf("Password is too short\n");
        printf("-------------------------------------------------\n");
        return 0;
    }

    for (int i = 0; i < length; i++) {
        char c = (char)password[i];
        if (isupper(c)) {
            uppercase = 1;
        } else if (islower(c)) {
            lowercase = 1;
        } else if (isdigit(c)) {
            digit = 1;
        } else if (ispunct(c)) {
            symbol = 1;
        }
    }

    if (uppercase) {
        score += 1;
    }

    if (lowercase) {
        score += 1;
    }

    if (digit) {
        score += 1;
    }

    if (symbol) {
        score += 1;
    }
    
    printf("\n---------- Password Strength --------------------\n");
    if (score >= 5) {
        printf("Password is Very Strong\n");
    } else if (score >= 4) {
        printf("Password is Strong\n");
    } else if (score >= 3) {
        printf("Password is Medium\n");
    } else if (score >= 2) {
        printf("Password is Weak\n");
    } else {
        printf("Password is Very Weak\n");
    }

    printf("Score: %d\n", score);
    printf("\n---------- Password Checker Details -------------\n");

    if (length < 8) {
        printf("Password needs to be at least 8 characters long\n");
    }

    if (!uppercase) {
        printf("Password needs an uppercase letter\n");
    }   

    if (!lowercase) {
        printf("Password needs a lowercase letter\n");
    }

    if (!digit) {
        printf("Password needs a number\n");
    }

    if (!symbol) {
        printf("Password needs a symbol\n");
    }

    return 0;
}