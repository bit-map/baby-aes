aes_cracker: aes_cracker.c aes.c
	gcc -o aes_cracker aes_cracker.c aes.c -I.
aes_decoder: aes_decoder.c aes.c
	gcc -o aes_decoder aes_decoder.c aes.c -I.
aes_cracker_lfsr: aes_cracker_lfsr.c aes.c
	gcc -o aes_cracker_lfsr aes_cracker_lfsr.c aes.c -I.
