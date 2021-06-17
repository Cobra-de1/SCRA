#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>

#include "SCRA.h"
#include "sha3.h"

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("Usage: ./verify signed_message public_key_filename");
        return 0;
    }

    public_key kp; /* Public Key */

    read_public_key(&kp, argv[2]);

    // printf("%s\n", mpz_get_str(NULL, 16, kp.n));
    // for (int i = 0; i < HASH_SIZE; i++) {
    //     printf("%02x", kp.pad[i]);
    // }
    // printf("\n%s\n", mpz_get_str(NULL, 16, kp.e));

    unsigned char msg[1000 * 1024];
    unsigned char hashed[HASH_SIZE];
    unsigned char sig[BLOCK_SIZE];
    int len = read_signed_message(msg, sizeof(msg), hashed, sig, &kp, argv[1]);

    // printf("\nMsg:\n");
    // for (int i = 0; i < len; i++) {
    //     printf("%02x", msg[i]);
    // }

    printf("\nRandom:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x", msg[len + i]);
    }

    printf("\nHashed:\n");
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", hashed[i]);
    }

    printf("\nSig:\n");
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("%02x", sig[i]);
    }

    int status = 0;
    double time = 0;

    for (int i = 0; i < 10000; i++) {
        time += verify(hashed, sig, &kp, &status);
    }
    

    if (status == 0) {
        printf("\n\nVerify success\n");
    } else {
        printf("\n\nVerify failed\n");
    }

    printf("\nTime verify(10000): %fms\n", time);

    clear_public_key(&kp);

    printf("\nDone\n");    

    return 0;
}
