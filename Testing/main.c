#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

int main(int argc, char** argv) {
    // Check arguments
    if (argc != 3) {
    fprintf(stderr, "Usage: %s message key\n", argv[0]);
    return 1;
    }

    // Read command line arguments
    const char* message = argv[1];
    const char* key_str = argv[2];

    // Convert the key from a hexadecimal string to an unsigned char array
    unsigned char key[EVP_MAX_KEY_LENGTH];
    int i;
    for (i = 0; i < EVP_MAX_KEY_LENGTH; i++) {
    sscanf(key_str + 2 * i, "%2hhx", &key[i]);
    }

    // Initialize the OpenSSL library
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Generate an RSA key pair
    RSA* rsa = RSA_new();
    BIGNUM* exponent = BN_new();
    BN_set_word(exponent, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, exponent, NULL);

    // Hash the message
    EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(hash_ctx, message, strlen(message));

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(hash_ctx, hash, &hash_len);

    // Encrypt the hash with the private key
    int rsa_len = RSA_size(rsa);
    unsigned char encrypted_hash[rsa_len];
    RSA_private_encrypt(hash_len, hash, encrypted_hash, rsa, RSA_PKCS1_PADDING);

    // Set up the cipher context for AES in CBC mode
    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cipher_ctx, EVP_aes_128_cbc(), NULL, key, NULL);

    // Determine the length of the encrypted message
    int encrypted_len;
    EVP_EncryptUpdate(cipher_ctx, NULL, &encrypted_len, message, strlen(message));
    encrypted_len += EVP_CIPHER_CTX_block_size(cipher_ctx);

    // Allocate a buffer for the encrypted message
    unsigned char encrypted_message[encrypted_len];

    // Encrypt the message with AES in CBC mode
    int len;
    EVP_EncryptUpdate(cipher_ctx, encrypted_message, &len, message, strlen(message));
    encrypted_len = len;
    EVP_EncryptFinal_ex(cipher_ctx, encrypted_message + len, &len);
    encrypted_len += len;

    // Concatenate encrypted hash and encrypted message
    unsigned char* signature = malloc(rsa_len + encrypted_len);
    memcpy(signature, encrypted_hash, rsa_len);
    memcpy(signature + rsa_len, encrypted_message, encrypted_len);

    // Send signature to recipient

    // Decrypt encrypted hash with public key
    unsigned char decrypted_hash[hash_len];
    RSA_public_decrypt(rsa_len, signature, decrypted_hash, rsa, RSA_PKCS1_PADDING);

    // Decrypt encrypted message with AES in CBC mode
    EVP_DecryptInit_ex(cipher_ctx, EVP_aes_128_cbc(), NULL, key, NULL);

    // Determine length of decrypted message
    int decrypted_len;
    EVP_DecryptUpdate(cipher_ctx, NULL, &decrypted_len, signature + rsa_len, encrypted_len);
    decrypted_len += EVP_CIPHER_CTX_block_size(cipher_ctx);

    // Allocate buffer for decrypted message
    unsigned char decrypted_message[decrypted_len];

    // Decrypt message
    EVP_DecryptUpdate(cipher_ctx, decrypted_message, &len, signature + rsa_len, encrypted_len);
    decrypted_len = len;
    EVP_DecryptFinal_ex(cipher_ctx, decrypted_message + len, &len);
    decrypted_len += len;

    // Hash decrypted message
    EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(hash_ctx, decrypted_message, decrypted_len);
    unsigned char new_hash[EVP_MAX_MD_SIZE];
    unsigned int new_hash_len;
    EVP_DigestFinal_ex(hash_ctx, new_hash, &new_hash_len);

    // Compare decrypted hash with newly-computed hash
    if (hash_len == new_hash_len && memcmp(hash, new_hash, hash_len) == 0) {
    // Digital signature is valid
    printf("Signature is valid\n");
    } else {
    // Digital signature is invalid
    printf("Signature is invalid\n");
    }

    // Clean up
    free(signature);
    RSA_free(rsa);
    BN_free(exponent);
    EVP_MD_CTX_free(hash_ctx);
    EVP_CIPHER_CTX_free(cipher_ctx);

    return 0;
}