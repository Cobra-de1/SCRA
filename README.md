# C++ SCRA implementation

## Decription

*Structure-free and Compact Real-time Authentication* (SCRA) implementation using standand C++ library and sha3-256 library for hash function

## Detail

Security: 128 bit

Digital signature base: C-RSA 3072 bit

Hash function: sha3-256

L = 32, b = 8

## How to run

This code is running in linux, if you use windows, recompile the SCRA.o and sha3.o by following:

- Go to folder `sha3` type `gcc -c sha3.c -o sha3.o`

- Copy new `sha3.o` and `sha3.h` into `SCRA` folder

- Go to folder `SCRA` and type `gcc -c SCRA.c -o SCRA.o -l sha3.o`

- Copy new `SCRA.o` and `sha3.o` in to `lib` folder 

### 1) Build with VisualStudio Code

### 2) Compile

gcc -g2 -O3 -DNDEBUG verify.c -o verify -L/lib -l:sha3.o -l:SCRA.o -I/include -Wall -lgmp

gcc -g2 -O3 -DNDEBUG verify.c -o verify -L/lib -l:sha3.o -l:SCRA.o -I/include -Wall -lgmp

gcc -g2 -O3 -DNDEBUG verify.c -o verify -L/lib -l:sha3.o -l:SCRA.o -I/include -Wall -lgmp

## References

Yavuz, A. A., Mudgerikar, A., Singla, A., Papapanagiotou, I., & Bertino, E. (2017). Real-time digital signatures for time-critical networks. IEEE Transactions on Information Forensics and Security, 12(11), 2627-2639.

https://github.com/mjosaarinen/tiny_sha3

https://github.com/ozgurozmen/FAAS/tree/master/faas_RSA
