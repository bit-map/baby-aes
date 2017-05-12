/*
Baby AES Cracker
John Kim
-----------
This code makes use of kokke's Tiny AES128 implementation, found at
https://github.com/kokke/tiny-AES128-C, which is released in the public domain
with no restrictions on usage under the Unlicense, found at
http://unlicense.org/.

Usage: aes_cracker cipher.txt iv.txt output.txt

Takes a text file cipher.txt containing a ciphertext, a second text file iv.txt
containing an "IV" of the first n bytes of the 16-byte AES-128 key used to
encrypt the plaintext, and creates a text file output.txt containing the full
AES-128 key. The program also prints to the command line with the full key as
well as the corresponding decrypted text blocks for visual inspection.

The methodology used to determine candidacy takes motivation from the EFF Def
Cracker, utilizing a brute force search method that iterates through all
possible AES-128 keys given an "IV", then runs a simple check on the decrypted
text for "English-ness", which is to say that each 1-byte character falls in the
range of 32-127. Of 256 possible 8-bit values, there are 96 valid characters.

For one block of 128-bit AES, which encrypts/decrypts in 16-byte blocks, there
is then a (96/256)^16 chance of a random key decrypting a single block with all
valid "English-like" ASCII characters. For 5 bytes of ambiguity, there are 2^40
possible keys, so checking one block for "English-ness" would still result in,
on average, ((96/256)^16)(2^40) = 168151.253906 "valid" blocks.

By decrypting two blocks and testing for "English-ness", for those same 2^40
possible keys, we drastically reduce the expected number of false positives to
(((96/256)^16)^2)(2^40) = 0.02571582098.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>

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

/*
Performs two rounds of checking for the validity of a key by the following
steps:
1. decrypts first 16-byte block of ciphertext cipher[] with AES-128 key key[] and
   stores the result in plain[]
2. checks every char of plain[] to see if it falls in ASCII range 32-127
3. repeats steps 1 and 2 with the second block, if it passed step 2

@param  *cipher  pointer to an array cipher[] holding up to two 16-byte blocks
                 of ciphertext
@param  *key     pointer to an array key[] holding the 16-byte AES-128 key
@param  *plain   pointer to an array plain[] which the function modifies to
                 store up to two 16-byte blocks of decrypted plaintext
@return          true   if both blocks decrypt to valid ASCII values,
                 false  otherwise
*/
bool is_english(uint8_t *cipher, uint8_t *key, uint8_t *plain)
{
  for (int i = 0; i < 2; i++)
  {
    AES128_ECB_decrypt(&cipher[i * 16], key, &plain[i * 16]);

    for (int j = 0; j < 16; j++)
    {
      // masking with E0 (1110 0000) is 0 for ASCII 0x1F and below
      // masking with 80 (1000 0000) is 1 for ASCII 0x80 and above
      if (!(plain[j + (i * 16)] & 0xE0) || (plain[j + (i * 16)] & 0x80))
        return false;
	  }
  }
  return true;
}

int main(int argc, char *argv[])
{
  FILE *fc, *fk, *fo;
  uint8_t ciphstr[64];
  uint8_t cipher[32];
  uint8_t ivstr[32] = {0};
  uint8_t iv[16] = {0};
  uint8_t key_i[16] = { 0xff, 0xff, 0xff, 0xff, \
                        0xff, 0xff, 0xff, 0xff, \
                        0xff, 0xff, 0xff, 0xff, \
                        0xff, 0xff, 0xff, 0xff };
  uint64_t key64_i, key64_f;
  int ivlen;

  clock_t start, end;
  double cpu_time_used;

  // for time measurement purposes
  start = clock();

  if (argc != 4)
  {
    printf("Usage: aes_cracker cipher.txt iv.txt output.txt\n");
    goto exit;
  }

  // try to open text files for reading/writing
  if(!(fc = fopen(argv[1], "r")))
  {
    printf ("Ciphertext file: %s could not be opened\n", argv[1]);
    goto exit;
  }
  if(!(fk = fopen(argv[2], "r")))
  {
    printf("IV file: %s could not be opened\n", argv[2]);
    goto exit;
  }
  if(!(fo = fopen(argv[3], "w")))
  {
    printf("Output file: %s could not be opened\n", argv[3]);
    goto exit;
  }

  // read in first 2 blocks of ciphertext and convert to hex
  fread(&ciphstr, 1, 64, fc);
  str_to_hex(ciphstr, cipher, 64);

  // read in IV (up to 32 ASCII characters) and convert to hex
  ivlen = fread(&ivstr, 1, 32, fk);
  str_to_hex(ivstr, iv, ivlen);

  // zero all the bytes in key_i where IV can go
  for (int i = 0; i < (ivlen / 2); i++)
  {
    key_i[i] = 0x00;
  }

  // fill in key_i with the IV
  for (int i = 0; i < 16; i++)
  {
    key_i[i] = key_i[i] | iv[i];
  }

  // put the least significant 8 bytes of key_i into a 64-bit int for looping
  key64_i = ((uint64_t)key_i[15]) | (((uint64_t)key_i[14]) << 8) | \
            (((uint64_t)key_i[13]) << 16) | (((uint64_t)key_i[12]) << 24) | \
            (((uint64_t)key_i[11]) << 32) | (((uint64_t)key_i[10]) << 40) | \
            (((uint64_t)key_i[9]) << 48) | (((uint64_t)key_i[8]) << 56);

  // put the least significant 8 bytes of iv into a 64-bit int for looping
  key64_f = ((uint64_t)iv[15]) | (((uint64_t)iv[14]) << 8) | \
            (((uint64_t)iv[13]) << 16) | (((uint64_t)iv[12]) << 24) | \
            (((uint64_t)iv[11]) << 32) | (((uint64_t)iv[10]) << 40) | \
            (((uint64_t)iv[9]) << 48) | (((uint64_t)iv[8]) << 56);

  uint8_t true_key[16];
  uint8_t true_plain[32];

  // main loop for testing each possible key
  for (uint64_t key_for = key64_i; key_for >= key64_f; key_for--)
  {
    uint8_t plain[32];
    uint8_t key[16] = { key_i[0], key_i[1], key_i[2], key_i[3], \
                        key_i[4], key_i[5], key_i[6], key_i[7], \
                        (uint8_t)(key_for >> 56), (uint8_t)(key_for >> 48), \
                        (uint8_t)(key_for >> 40), (uint8_t)(key_for >> 32), \
                        (uint8_t)(key_for >> 24), (uint8_t)(key_for >> 16), \
                        (uint8_t)(key_for >> 8), (uint8_t)(key_for) };

    // copies key and plaintext blocks once it passes the english test
    // and breaks out of the loop
    if (is_english(cipher, key, plain))
    {
      memcpy(true_key, key, 16 * sizeof(uint8_t));
      memcpy(true_plain, plain, 32 * sizeof(uint8_t));
      break;
    }
  }

  // print full key and partial plaintext to console
  printf("Key: ");
  for (int i = 0; i < 16; i++)
  {
    printf("%02X", true_key[i]);
  }
  printf("\n");

  printf("First two plaintext blocks: ");
  for (int i = 0; i < 32; i++)
  {
    printf("%c", true_plain[i]);
  }
  printf("\n");

  // write full key to output file
  for (int i = 0; i < 16; i++)
  {
    fprintf(fo, "%02X", true_key[i]);
  }
  fprintf(fo, "\n");

// clean up and close opened files
exit:

  if (fk)
    fclose(fk);

  if (fc)
    fclose(fc);

  if (fo)
    fclose(fo);

  // measure time and print to console
  end = clock();
  cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
  printf("Time taken: %.3f sec", cpu_time_used);
}
