/*
specifically built for 5-byte key
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
  uint64_t lfsr = 1;
  uint64_t bit;
  // main loop for testing each possible key
  while(true)
  {
    // lsfr stuff -> XNOR taps from 40, 38, 21, 19 for 40-bit maximal LFSR
    bit = ~(~(~((lfsr >> 0) ^ (lfsr >> 2)) ^ (lfsr >> 19)) ^ (lfsr >> 21)) & 1;
    lfsr = (lfsr >> 1) | (bit << 39);
    //printf("%016llX\n", lfsr);

    uint8_t plain[32];
    uint8_t key[16] = { key_i[0], key_i[1], key_i[2], key_i[3], \
                        key_i[4], key_i[5], key_i[6], key_i[7], \
                        key_i[8], key_i[9], key_i[10], \
                        (uint8_t)(lfsr >> 32), (uint8_t)(lfsr >> 24), \
                        (uint8_t)(lfsr >> 16), (uint8_t)(lfsr >> 8), \
                        (uint8_t)(lfsr) };
    /*
    printf("Testing key: ");
    for (int i = 0; i < 16; i++)
    {
      printf("%02X", key[i]);
    }
    printf("\n");
    */

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
