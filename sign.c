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

    if (argc < 3) {
        printf("Usage: ./sign message public_key_filename private_key_filename");
        return 0;
    }

    public_key kp; /* Public Key */
    private_key ku; /* Private Key */

    read_public_key(&kp, argv[2]);
    read_private_key(&ku, argv[3]);

    printf("%s\n", mpz_get_str(NULL, 16, kp.n));
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", kp.pad[i]);
    }
    printf("\n%s\n", mpz_get_str(NULL, 16, kp.e));
    printf("%s\n", mpz_get_str(NULL, 16, ku.d));

    unsigned char msg[1000 * 1024];
    unsigned char hashed[HASH_SIZE];
    int len = read_message(msg, sizeof(msg), hashed, &kp, argv[1]);

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

    unsigned char sig[BLOCK_SIZE];

    double time = 0;
    
    for (int i = 0; i < 10000; i++) {
        time += sign(hashed, sig, &ku);
    }

    printf("\nSig:\n");
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("%02x", sig[i]);
    }

    printf("\n\nTime sign(10000): %fms\n", time);
    
    save_signed_message(msg, len, sig, argv[1]);

    clear_public_key(&kp);
    clear_private_key(&ku);

    printf("\nDone\n");    

    return 0;
}
