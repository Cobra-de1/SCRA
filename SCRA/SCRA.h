#ifndef __SCRA_H__
#define __SCRA_H__

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>

#include "sha3.h"

#define MODULUS_SIZE 3072                       /* This is the number of bits we want in the modulus */
#define BLOCK_SIZE (MODULUS_SIZE / 8)           /* This is the size of a block that gets en/decrypted at once */
#define BUFFER_SIZE ((MODULUS_SIZE / 8) / 2)    /* This is the number of bytes in n and p */
#define HASH_SIZE 32                            /* This is size of choosen hash function, hash_size = hash_function_length // 8 */
#define HASH_BLOCK_NUM 32                       /* This is size of l */
#define HASH_BLOCK_LEN 256                      /* This is size of b, hash_block_len = 2 ^ b */
#define CONCAT_LEN (HASH_SIZE + 2)              /* This is length of (i||Mi||P) */

typedef struct {
    mpz_t n;                /* Modulus */
    mpz_t e;                /* Public Exponent */
    unsigned char pad[HASH_SIZE];    /* Padding */
} public_key;

typedef struct {
    mpz_t n; /* Modulus */
    mpz_t d; /* Private Exponent */
    mpz_t table[HASH_BLOCK_NUM][HASH_BLOCK_LEN]; /* Precompute Table */
} private_key;

// Generate 2 key
void generate_keys(public_key* kp, private_key* ku);

// Clear memory
void clear_public_key(public_key* kp);
void clear_private_key(private_key *ku);

// Save key to file
void save_public_key(public_key* kp, char* path);
void save_private_key(private_key* ku, char* path);

// Read key from file
void read_public_key(public_key* kp, char* path);
void read_private_key(private_key* ku, char* path);

// Read message from file
int read_message(unsigned char* msg, size_t size, unsigned char* hashed, public_key* kp, char* path);
int read_signed_message(unsigned char* msg, size_t size, unsigned char* hashed, unsigned char* sig, public_key* kp, char* path);

// Save signed message
void save_signed_message(unsigned char* msg, size_t size, unsigned char* sig,  char* path);

// Sign
double sign(unsigned char* msg, unsigned char* sig, private_key* ku);

// Verify
double verify(unsigned char* msg, unsigned char* sig, public_key* kp, int* status);

#endif