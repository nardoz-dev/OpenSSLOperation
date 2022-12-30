#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#define AES_BLOCK_SIZE 16

void decrypt(unsigned char* ciphertext,size_t ciphertext_len, unsigned char* key, unsigned char* iv){

   //ALlocate a buffer for the plaintext
   unsigned char new_plaintext[ciphertext_len];
   // Set up the AES context
    AES_KEY aes_key_2;
    AES_set_decrypt_key(key, 8 * AES_BLOCK_SIZE, &aes_key_2);

    // Decrypt the ciphertext
    AES_cbc_encrypt(ciphertext,new_plaintext, ciphertext_len, &aes_key_2, iv, AES_DECRYPT);

    int porcodio=12;
    // Print the plaintext as a string
    printf("%.*s\n",porcodio, new_plaintext);
    printf("%s\n", new_plaintext);
}


int main(int argc, char** argv) {
    // Check arguments
    if (argc != 4) {
    fprintf(stderr, "Usage: %s plaintext key iv\n", argv[0]);
    return 1;
    }

    // Read command line arguments
    const char* plaintext = argv[1];
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

    // Determine the length of the plaintext and allocate a buffer for the ciphertext
    size_t plaintext_len = strlen(plaintext);
    size_t ciphertext_len = plaintext_len + AES_BLOCK_SIZE;
    unsigned char ciphertext[ciphertext_len]; 

    // Set up the AES context
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 8 * AES_BLOCK_SIZE, &aes_key);

    // Encrypt the plaintext
    AES_cbc_encrypt((unsigned char*)plaintext, ciphertext, plaintext_len, &aes_key, iv, AES_ENCRYPT);

    // Print the ciphertext as a hexadecimal string
    for (i = 0; i < ciphertext_len; i++) {
    printf("%02x", ciphertext[i]);
    }
    printf("\n");

    decrypt(ciphertext,ciphertext_len, key, iv);

    return 0;
}