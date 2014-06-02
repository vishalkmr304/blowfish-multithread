/*
blowfish.h:  Header file for blowfish.c

Copyright (C) 1997 by Paul Kocher

Modified by Alessandro Renzi (alessandro.renzi@about.me) for multithread implementation
*/

#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>


/**
 * Context generated according to the provided key
 * 
 * @see Blowfish_Init()
 */
typedef struct {
  uint32_t P[16 + 2];	//! P boxes
  uint32_t S[4][256];	//! S boxes
} BLOWFISH_CTX;


void Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen);

void Blowfish_Encrypt(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr);
void Blowfish_Decrypt(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr);

uint64_t BlowfishEncryption(BLOWFISH_CTX *ctx, uint64_t x);
uint64_t BlowfishDecryption(BLOWFISH_CTX *ctx, uint64_t x);


#endif

