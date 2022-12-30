#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#define AES_BLOCK_SIZE 16

int main(int argc, char** argv) {
// Check arguments
if (argc != 4) {
fprintf(stderr, "Usage: %s ciphertext key iv\n", argv[0]);
return 1;
}

// Read command line arguments
const char* ciphertext_str = argv[1];
const char* key_str = argv[2];
const char* iv_str = argv[3];

// Convert key and IV from strings to unsigned char arrays
unsigned char key[AES_BLOCK_SIZE];
unsigned char iv[AES_BLOCK_SIZE];
int i;
for (i = 0; i < AES_BLOCK_SIZE; i++) {
    sscanf(key_str + 2 * i, "%2hhx", &key[i]);
    sscanf(iv_str + 2 * i, "%2hhx", &iv[i]);
}

// Convert the ciphertext from a hexadecimal string to an unsigned char array
size_t ciphertext_len = strlen(ciphertext_str) / 2;
printf("ciphertext_len = %ld", ciphertext_len);
unsigned char ciphertext[ciphertext_len];
for (i = 0; i < ciphertext_len; i++) {
sscanf(ciphertext_str + 2 * i, "%2hhx", &ciphertext[i]);
}


// Allocate a buffer for the plaintext
unsigned char plaintext[ciphertext_len];
printf("ciphertext_len = %ld", ciphertext_len);

// Set up the AES context
AES_KEY aes_key;
AES_set_decrypt_key(key, 8 * AES_BLOCK_SIZE, &aes_key);

// Decrypt the ciphertext
AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &aes_key, iv, AES_DECRYPT);

// Print the plaintext as a string
printf("%s\n", plaintext);

return 0;
}