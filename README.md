# Baby AES Cracker
A simple AES-128 brute-force cracker written for a network security course project.
## Overview
This code makes use of [kokke's Tiny AES128](https://github.com/kokke/tiny-AES128-C) implementation.

The methodology used to determine candidacy takes motivation from the EFF Def Cracker, utilizing a brute force search method that iterates through all possible AES-128 keys given an "IV", then runs a simple check on the decrypted text for "English-ness", which is to say that each 1-byte character falls in the range of 32-127. Of 256 possible 8-bit values, there are 96 valid characters.

For one block of 128-bit AES, which encrypts/decrypts in 16-byte blocks, there is then a (96/256)^16 chance of a random key decrypting a single block with all valid "English-like" ASCII characters. For 5 bytes of ambiguity, there are 2<sup>40</sup> possible keys, so checking one block for "English-ness" would still result in, on average, ((96/256)<sup>16</sup>)(2<sup>40</sup>) = 168151.253906 "valid" blocks.

By decrypting two blocks and testing for "English-ness", for those same 2<sup>40</sup> possible keys, we drastically reduce the expected number of false positives to (((96/256)<sup>16</sup>)<sup>2</sup>)(2<sup>40</sup>) = 0.02571582098.

Because brute-forcing AES-128 is practically unfeasible, the original assignment used "initialization vector" (IV) files (inspired by the infamous WEP algorithm) which gave the first n bits of the full 128-bit key. This makes the Baby AES Cracker impractical for pretty much anything. Additionally, because the program assumes "English-ness" (ASCII plaintext), it is, of course, useless for pretty much anything else.
## Usage
The included binaries are built for Windows and require Cygwin to be installed. 
First, run `aes_cracker` with `aes_cracker cipher.txt iv.txt key.txt` where all input files are plain text files, and the output file is the full key.
Then, run `aes_decoder` with `aes_decoder cipher.txt key.txt plain.txt` where `key.txt` is the key from running `aes_cracker`.
`aes_cracker_lfsr` implements a hard-wired 40-bit linear feedback shift register for testing keys in non-sequential order. The usage is the same as `aes_cracker` but assumes 88 bits of the 128-bit keys are already known through the IV. The average theoretical runtime is approximately the same but since only the one correct key needs to be found, there are cases in which this should outperform `aes_cracker`.
