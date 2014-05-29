/*
blowfish.h:  Header file for blowfish.c

Copyright (C) 1997 by Paul Kocher

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


See blowfish.c for more information about this file.


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

