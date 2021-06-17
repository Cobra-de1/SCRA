#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>

#include "SCRA.h"
#include "sha3.h"

void generate_keys(public_key* kp, private_key* ku) {
    // Initialize public key
    mpz_init(kp->n);
    mpz_init(kp->e);

    // Initialize private key
    mpz_init(ku->n);
    mpz_init(ku->d);

    unsigned char buf[BUFFER_SIZE];
    int i;
    mpz_t phi; mpz_init(phi);
    mpz_t tmp1; mpz_init(tmp1);
    mpz_t tmp2; mpz_init(tmp2);
    mpz_t p; mpz_init(p);
    mpz_t q; mpz_init(q);

    srand(time(NULL));

    /* Instead of selecting e st. gcd(phi, e) = 1; 1 < e < phi, lets choose e
     * first then pick p,q st. gcd(e, p-1) = gcd(e, q-1) = 1 */
    // We'll set e globally.  I've seen suggestions to use primes like 3, 17 or
    // 65537, as they make coming calculations faster.  Lets use 3.
    mpz_set_ui(kp->e, 65537);

    /* Select p and q */
    /* Start with p */
    // Set the bits of tmp randomly
    for(i = 0; i < BUFFER_SIZE; i++) {
        buf[i] = rand() % 0xFF;
    }
    // Set the top two bits to 1 to ensure int(tmp) is relatively large
    buf[0] |= 0xC0;
    // Set the bottom bit to 1 to ensure int(tmp) is odd (better for finding primes)
    buf[BUFFER_SIZE - 1] |= 0x01;
    // Interpret this char buffer as an int
    mpz_import(tmp1, BUFFER_SIZE, 1, sizeof(buf[0]), 0, 0, buf);
    // Pick the next prime starting from that random number
    mpz_nextprime(p, tmp1);
    /* Make sure this is a good choice*/
    mpz_mod(tmp2, p, kp->e);        /* If p mod e == 1, gcd(phi, e) != 1 */
    while(!mpz_cmp_ui(tmp2, 1))
    {
        mpz_nextprime(p, p);    /* so choose the next prime */
        mpz_mod(tmp2, p, kp->e);
    }

    /* Now select q */
    do {
        for(i = 0; i < BUFFER_SIZE; i++) {
            buf[i] = rand() % 0xFF;
        }
        // Set the top two bits to 1 to ensure int(tmp) is relatively large
        buf[0] |= 0xC0;
        // Set the bottom bit to 1 to ensure int(tmp) is odd
        buf[BUFFER_SIZE - 1] |= 0x01;
        // Interpret this char buffer as an int
        mpz_import(tmp1, (BUFFER_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
        // Pick the next prime starting from that random number
        mpz_nextprime(q, tmp1);
        mpz_mod(tmp2, q, kp->e);
        while(!mpz_cmp_ui(tmp2, 1))
        {
            mpz_nextprime(q, q);
            mpz_mod(tmp2, q, kp->e);
        }
    } while(mpz_cmp(p, q) == 0); /* If we have identical primes (unlikely), try again */

    /* Calculate n = p x q */
    mpz_mul(ku->n, p, q);

    /* Compute phi(n) = (p-1)(q-1) */
    mpz_sub_ui(tmp1, p, 1);
    mpz_sub_ui(tmp2, q, 1);
    mpz_mul(phi, tmp1, tmp2);

    /* Calculate d (multiplicative inverse of e mod phi) */
    if(mpz_invert(ku->d, kp->e, phi) == 0)
    {
        mpz_gcd(tmp1, kp->e, phi);
        printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, tmp1));
        printf("Invert failed\n");
        exit(0);
    }

    /* Set public key */
    mpz_set(kp->n, ku->n);

    /* Random padding */
    // Set the bits of padding randomly
    for(i = 0; i < HASH_SIZE; i++) {
        kp->pad[i] = rand() % 0xFF;    
    }

    /* Precompute table */
    unsigned char mij[CONCAT_LEN];
    unsigned char hashed[HASH_SIZE];

    for (int i = 0; i < HASH_BLOCK_NUM; i++) {
        for (int j = 0; j < HASH_BLOCK_LEN; j++) {
            mpz_init(ku->table[i][j]);            
            mij[0] = i;
            mij[1] = j;
            for (int z = 0; z < HASH_SIZE; z++) {
                mij[z + 2] = kp->pad[z];
                hashed[z] = 0;
            }
            sha3(mij, CONCAT_LEN, hashed, HASH_SIZE);
            mpz_import(tmp1, HASH_SIZE, 1, sizeof(hashed[0]), 0, 0, hashed);
            // table[i][j] = (hash(i||j||p) ^ d) % n
            mpz_powm(ku->table[i][j], tmp1, ku->d, ku->n);
        }
    }

    /* Clear memory */
    mpz_clear(tmp1);
    mpz_clear(tmp2);
    mpz_clear(p);   
    mpz_clear(q);
    mpz_clear(phi);

}

void clear_public_key(public_key* kp) {
    // Public key
    mpz_clear(kp->n);
    mpz_clear(kp->e);
}

void clear_private_key(private_key *ku) {
    // Private key
    mpz_clear(ku->n);
    mpz_clear(ku->d);
    for (int i = 0; i < HASH_BLOCK_NUM; i++) {
        for (int j = 0; j < HASH_BLOCK_LEN; j++) {
            mpz_clear(ku->table[i][j]);
        }
    }
}

void save_public_key(public_key* kp, char* path) {
    FILE* fp = fopen(path, "wb");
    if (fp == NULL) {
        printf("%s not valid\n", path);
        exit(0);
    }
    unsigned char buf[BLOCK_SIZE];
    // Save modulus
    mpz_export(buf, NULL, 1, sizeof(buf[0]), 0, 0, kp->n);
    fwrite(buf, sizeof(buf[0]), BLOCK_SIZE, fp);
    // Save padding
    fwrite(kp->pad, sizeof(kp->pad[0]), HASH_SIZE, fp);
    // Save public exponent
    mpz_export(buf, NULL, 1, sizeof(buf[0]), 0, 0, kp->e);
    int numb = 8 * sizeof(buf[0]);
    // Count number of byte in e
    size_t count = (mpz_sizeinbase (kp->e, 2) + numb - 1) / numb;
    fwrite(buf, sizeof(buf[0]), count, fp);
    fclose(fp);
}

void save_private_key(private_key* ku, char* path) {
    FILE* fp = fopen(path, "wb");
    if (fp == NULL) {
        printf("%s not valid\n", path);
        exit(0);
    }
    unsigned char buf[BLOCK_SIZE];
    // Save modulus
    mpz_export(buf, NULL, 1, sizeof(buf[0]), 0, 0, ku->n);
    fwrite(buf, sizeof(buf[0]), BLOCK_SIZE, fp);
    // Save table
    for (int i = 0; i < HASH_BLOCK_NUM; i++) {
        for (int j = 0; j < HASH_BLOCK_LEN; j++) {
            int count = BLOCK_SIZE - (mpz_sizeinbase (ku->table[i][j], 2) + 7) / 8;
            for (int z = 0; z < count; z++) {
                buf[z] = 0;
            }
            mpz_export(buf + count, NULL, 1, sizeof(buf[0]), 0, 0, ku->table[i][j]);
            fwrite(buf, sizeof(buf[0]), BLOCK_SIZE, fp);
        }
    }
    // Save private exponent
    mpz_export(buf, NULL, 1, sizeof(buf[0]), 0, 0, ku->d);
    // Count number of byte in e
    size_t count = (mpz_sizeinbase (ku->d, 2) + 7) / 8;
    fwrite(buf, sizeof(buf[0]), count, fp);
    fclose(fp);
}

void read_public_key(public_key* kp, char* path) {
    FILE* fp = fopen(path, "rb");
    if (fp == NULL) {
        printf("%s not valid\n", path);
        exit(0);
    }
    // Initialize public key
    mpz_init(kp->n);
    mpz_init(kp->e);

    unsigned char tmp[BLOCK_SIZE];
    // Read modulus
    fread(tmp, sizeof(tmp[0]), BLOCK_SIZE, fp);
    mpz_import(kp->n, (BLOCK_SIZE), 1, sizeof(tmp[0]), 0, 0, tmp);

    // Read padding
    fread(kp->pad, sizeof(kp->pad[0]), HASH_SIZE, fp);

    // Read public exponent
    size_t count = fread(tmp, sizeof(tmp[0]), BUFFER_SIZE, fp);
    mpz_import(kp->e, (count), 1, sizeof(tmp[0]), 0, 0, tmp);
    fclose(fp);
}

void read_private_key(private_key* ku, char* path) {
    FILE* fp = fopen(path, "rb");
    if (fp == NULL) {
        printf("%s not valid\n", path);
        exit(0);
    }
    // Initialize private key
    mpz_init(ku->n);
    mpz_init(ku->d);

    unsigned char tmp[BLOCK_SIZE];
    // Read modulus
    fread(tmp, sizeof(tmp[0]), BLOCK_SIZE, fp);
    mpz_import(ku->n, (BLOCK_SIZE), 1, sizeof(tmp[0]), 0, 0, tmp);

    // Read table
    for (int i = 0; i < HASH_BLOCK_NUM; i++) {
        for (int j = 0; j < HASH_BLOCK_LEN; j++) {
            mpz_init(ku->table[i][j]);
            fread(tmp, sizeof(tmp[0]), BLOCK_SIZE, fp);
            mpz_import(ku->table[i][j], (BLOCK_SIZE), 1, sizeof(tmp[0]), 0, 0, tmp);            
        }
    }

    // Read private exponent
    size_t count = fread(tmp, sizeof(tmp[0]), BLOCK_SIZE, fp);
    mpz_import(ku->d, (count), 1, sizeof(tmp[0]), 0, 0, tmp);
    fclose(fp);
}

int read_message(unsigned char* msg, size_t size, unsigned char* hashed, public_key* kp, char* path) {
    FILE* fp = fopen(path, "rb");
    if (fp == NULL) {
        printf("%s not valid\n", path);
        exit(0);
    }
    size_t len = fread(msg, sizeof(msg[0]), size - 16, fp);
    srand(time(NULL));
    for (int i = 0; i < 16; i++) {
        msg[len + i] = rand() % 0xFF;
    }
    sha3(msg, len + 16, hashed, HASH_SIZE);
    fclose(fp);
    return len;
}

int read_signed_message(unsigned char* msg, size_t size, unsigned char* hashed, unsigned char* sig, public_key* kp, char* path) {
    FILE* fp = fopen(path, "rb");
    if (fp == NULL) {
        printf("%s not valid\n", path);
        exit(0);
    }
    size_t len = fread(msg, sizeof(msg[0]), size, fp);
    len -= BLOCK_SIZE;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        sig[i] = msg[len + i];
    }
    len -= 16;
    sha3(msg, len + 16, hashed, HASH_SIZE);
    fclose(fp);
    return len;
}

void save_signed_message(unsigned char* msg, size_t size, unsigned char* sig,  char* path) {
    char *new_path = malloc(strlen(path) + strlen("_signed") + 1);
    strcpy(new_path, path);
    strcat(new_path, "_signed");
    FILE* fp = fopen(new_path, "wb");
    if (fp == NULL) {
        printf("%s not valid\n", new_path);
        free(new_path);
        exit(0);
    }   
    fwrite(msg, sizeof(msg[0]), size + 16, fp);
    fwrite(sig, sizeof(sig[0]), BLOCK_SIZE, fp);
    fclose(fp);
    free(new_path);
}

double sign(unsigned char* msg, unsigned char* sig, private_key* ku) {
    int start = clock();
    mpz_t mul;
    mpz_init(mul);
    mpz_set_ui(mul, 1);

    for (int i = 0; i < HASH_BLOCK_NUM; i++) {
        mpz_mul(mul, mul, ku->table[i][(unsigned int)msg[i]]);
        mpz_mod(mul, mul, ku->n);
    }
    mpz_export(sig, NULL, 1, sizeof(sig[0]), 0, 0, mul);
    mpz_clear(mul);
    int end = clock();
    return (double)(end - start) / CLOCKS_PER_SEC * 1000;
}

double verify(unsigned char* msg, unsigned char* sig, public_key* kp, int* status) {
    int start = clock();
    mpz_t mul;
    mpz_init(mul);
    mpz_import(mul, (BLOCK_SIZE), 1, sizeof(sig[0]), 0, 0, sig);
    mpz_powm(mul, mul, kp->e, kp->n);

    mpz_t tmp;
    mpz_init(tmp);
    mpz_set_ui(tmp, 1);

    mpz_t tmp2;
    mpz_init(tmp2);

    for (int i = 0; i < HASH_BLOCK_NUM; i++) {
        unsigned char mij[CONCAT_LEN];
        unsigned char hashed[HASH_SIZE];
        mij[0] = i;
        mij[1] = msg[i];
        for (int j = 0; j < HASH_SIZE; j++) {
            mij[j + 2] = kp->pad[j];
        }
        sha3(mij, CONCAT_LEN, hashed, HASH_SIZE);
        mpz_import(tmp2, HASH_SIZE, 1, sizeof(hashed[0]), 0, 0, hashed);
        mpz_mul(tmp, tmp, tmp2);
        mpz_mod(tmp, tmp, kp->n);
    }
    *status = mpz_cmp(mul, tmp);    
    mpz_clear(mul);
    mpz_clear(tmp);
    mpz_clear(tmp2);
    int end = clock();
    return (double)(end - start) / CLOCKS_PER_SEC * 1000;
}