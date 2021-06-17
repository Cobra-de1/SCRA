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
        printf("Usage: ./generate_key public_key_filename private_key_filename");
        return 0;
    }

    public_key kp; /* Public Key */
    private_key ku; /* Private Key */

    generate_keys(&kp, &ku);

    printf("Generate key done\n");

    printf("n: %s\n", mpz_get_str(NULL, 16, kp.n));
    printf("pad: ");
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", kp.pad[i]);
    }
    printf("\ne: %s\n", mpz_get_str(NULL, 16, kp.e));
    printf("d: %s\n", mpz_get_str(NULL, 16, ku.d));

    save_public_key(&kp, argv[1]);
    printf("Save public done\n");    
    save_private_key(&ku, argv[2]);
    printf("Save private done\n");

    clear_public_key(&kp);
    clear_private_key(&ku);

    printf("Done\n");    

    return 0;
}
