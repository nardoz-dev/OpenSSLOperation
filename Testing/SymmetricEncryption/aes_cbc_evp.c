#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

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
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int i;
    for (i = 0; i < EVP_MAX_KEY_LENGTH; i++) {
    sscanf(key_str + 2 * i, "%2hhx", &key[i]);
    }
    for (i = 0; i < EVP_MAX_IV_LENGTH; i++) {
    sscanf(iv_str + 2 * i, "%2hhx", &iv[i]);
    }

    // Initialize the OpenSSL library
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Set up the cipher context
    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cipher_ctx, EVP_aes_128_cbc(), NULL, key, iv);

    // Determine the length of the ciphertext
    int ciphertext_len;
    EVP_EncryptUpdate(cipher_ctx, NULL, &ciphertext_len, (unsigned char*)plaintext, strlen(plaintext));
    ciphertext_len += EVP_CIPHER_CTX_block_size(cipher_ctx);

    // Allocate a buffer for the ciphertext
    unsigned char ciphertext[ciphertext_len];

    // Encrypt the plaintext
    int len;
    EVP_EncryptUpdate(cipher_ctx, ciphertext, &len, (unsigned char*)plaintext, strlen(plaintext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(cipher_ctx, ciphertext + len, &len);
    ciphertext_len += len;

    // Print the ciphertext as a hexadecimal string
    for (i = 0; i < ciphertext_len; i++) {
    printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Clean up
    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}