#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>

int main ( int argc, char** argv) {
    // Check arguments
    if (argc != 4) {
        fprintf(stderr, "Usage: %s ciphertext key iv\n", argv[0]);
        return 1;
    }

    // Read command line arguments
    const char* ciphertext_str = argv[1];
    const char* key_str = argv[2];
    const char* iv_str = argv[3];

    // Convert key and IV from strings to unsigned char arrays      ==>   Global?
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int i;
    for ( i = 0 ; i < EVP_MAX_KEY_LENGTH ; i++)
        sscanf(key_str + 2 * i, "%2hhx", &key[i]);
    for ( i = 0 ; i < EVP_MAX_IV_LENGTH ; i++)
        sscanf(iv_str + 2 * i, "%2hhx", &iv[i]);

    // Convertiamo the ciphertext from a hexadecimal string to an unsigned char array
    size_t ciphertext_len = strlen(ciphertext_str) / 2;
    unsigned char ciphertext[ciphertext_len];
    for (i = 0; i < ciphertext_len; i++) {
        sscanf(ciphertext_str + 2 * i, "%2hhx", &ciphertext[i]);
    }

    //Initialize the OpenSSL library   ==> Initialization out the main ?
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    //Set up the cipher context
    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(cipher_ctx, EVP_aes_128_cbc(), NULL, key, iv);

    //Determine the length of the plaintext
    int plaintext_len;

    EVP_DecryptUpdate(cipher_ctx, NULL, &plaintext_len, ciphertext, ciphertext_len);
    plaintext_len += EVP_CIPHER_CTX_block_size(cipher_ctx);

    // Allocate a buffer for the plaintext
    unsigned char plaintext[plaintext_len];

    // Decrypt the ciphertext
    int len;
    EVP_DecryptUpdate(cipher_ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(cipher_ctx, plaintext + len, &len);
    plaintext_len += len;

    // Print the plaintext as a string
    printf("%.*s\n", plaintext_len, plaintext);
    
    // Clean up
    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
