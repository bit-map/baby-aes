/*
AES Decoder
John Kim
-----------
This code makes use of kokke's Tiny AES128 implementation, found at
https://github.com/kokke/tiny-AES128-C, which is released in the public domain
with no restrictions on usage under the Unlicense, found at
http://unlicense.org/.

Usage: aes_decoder cipher.txt key.txt output.txt

Takes a text file cipher.txt containing a ciphertext, a second text file key.txt
containing the full 16-byte AES-128 key, and creates a text file output.txt
containing the full decoded plaintext.

A simple helper program to the Baby AES Cracker.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CBC 0
#define ECB 1

#include "aes.h"

/*
Takes a string of ASCII characters str[] and converts to hex bytes, which it
stores in hex[].
eg. "AE" = { 0x41, 0x45 } in str[] is stored in hex[] as 0xAE.

This function is taken largely wholesale from example file aesxam.c from Brian
Gladman's C/C++ implementation of AES-128, which can be found at
https://github.com/BrianGladman/AES.

---------------------------------------------------------------------------
Copyright (c) 1998-2013, Brian Gladman, Worcester, UK. All rights reserved.
The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:
  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;
  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.
This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 20/12/2007

@param  *str  pointer to an array str[] of n 1-byte ASCII characters
@param  *hex  pointer to an array hex[] which the function modifies to store n/2
              8-bit hex pairs
@param  n     unsigned length, in bytes, of array str[]
*/
void str_to_hex(uint8_t *str, uint8_t *hex, int n)
{
  int by = 0;
  for (int i = 0; i < n; i++)
  {
    if(str[i] >= '0' && str[i] <= '9')
      by = (by << 4) + str[i] - '0';
    else if(str[i] >= 'A' && str[i] <= 'F')
      by = (by << 4) + str[i] - 'A' + 10;
    hex[i / 2] = by & 0xff;
  }
}

int main(int argc, char *argv[])
{
  FILE *fc, *fk, *fo;
  uint8_t ciphstr[128];
  uint8_t cipher[64];
  uint8_t plain[64];
  uint8_t keystr[32] = {0};
  uint8_t key[16] = {0};

  if (argc != 4)
  {
    printf ("Usage: aes_decoder cipher.txt key.txt output.txt\n");
    goto exit;
  }

  // try to open text files for reading/writing
  if(!(fc = fopen (argv[1], "r")))
  {
    printf ("Ciphertext file: %s could not be opened\n", argv[1]);
    goto exit;
  }
  if(!(fk = fopen (argv[2], "r")))
  {
    printf ("Key file: %s could not be opened\n", argv[2]);
    goto exit;
  }
  if(!(fo = fopen (argv[3], "w")))
  {
    printf ("Output file: %s could not be opened\n", argv[3]);
    goto exit;
  }

  // read in all 4 blocks of ciphertext and convert to hex
  fread(&ciphstr, 1, 128, fc);
  str_to_hex(ciphstr, cipher, 128);

  // read in key (32 ASCII characters) and convert to hex
  fread(&keystr, 1, 32, fk);
  str_to_hex(keystr, key, 32);

  AES128_ECB_decrypt(&cipher[0], key, &plain[0]);
  AES128_ECB_decrypt(&cipher[16], key, &plain[16]);
  AES128_ECB_decrypt(&cipher[32], key, &plain[32]);
  AES128_ECB_decrypt(&cipher[48], key, &plain[48]);

  printf("Full plaintext: ");
  for (int i = 0; i < 64; i++)
  {
    printf("%c", plain[i]);
  }
  printf("\n");

  fwrite(plain, sizeof(uint8_t), 64, fo);

exit:
  if (fk)
    fclose (fk);

  if (fc)
    fclose (fc);

  if (fo)
    fclose (fo);

}
