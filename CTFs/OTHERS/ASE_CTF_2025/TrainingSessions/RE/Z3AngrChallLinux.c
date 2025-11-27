#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main() {
    char buf[128];

    printf("Enter password: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return 1;

    int len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') {
        buf[len-1] = '\0';
        len--;
    }

    if (len != 8) {
        printf("Wrong length!\n");
        return 0;
    }

    unsigned char *p = (unsigned char*)buf;

    // Constraint 1: first three chars sum
    if ((int)p[0] + (int)p[1] + (int)p[2] != 285) {
        printf("Nope.\n");
        return 0;
    }

    // Constraint 2: p3 and p4 relation
    if (((int)p[3] * 2 + (int)p[4]) != 231) {
        printf("Nope.\n");
        return 0;
    }

    // Constraint 3: XOR between p5 and p6
    if ((p[5] ^ p[6]) != 40) {
        printf("Nope.\n");
        return 0;
    }

    // Constraint 4: sum of last two
    if ((int)p[6] + (int)p[7] != 115) {
        printf("Nope.\n");
        return 0;
    }

    // Constraint 5: fancy mix
    if ((((int)p[0] - (int)p[7]) ^ (int)p[2]) != 68) {
        printf("Nope.\n");
        return 0;
    }

    // Constraint 6: some scattered sum
    if ((int)p[1] + (int)p[5] + (int)p[7] != 271) {
        printf("Nope.\n");
        return 0;
    }

    // Constraint 7: linear combo in middle
    if (((int)p[2] + (int)p[3]) * 3 - (int)p[4] != 525) {
        printf("Nope.\n");
        return 0;
    }

    // Final global sum
    int sum = 0;
    for (int i = 0; i < 8; ++i) sum += p[i];
    if (sum != 663) {
        printf("Nope.\n");
        return 0;
    }

    printf("Correct password!\n");
    return 0;
}
