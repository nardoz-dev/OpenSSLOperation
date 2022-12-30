#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

int main(int argc, char** argv) {
// Check command line arguments
if (argc != 3) {
fprintf(stderr, "Usage: %s message key\n", argv[0]);
return 1;
}

// Read arguments
const char* message = argv[1];
const char* key_str = argv[2];

// Convert key from hexadecimal string to unsigned char array
unsigned char key[EVP_MAX_KEY_LENGTH];
int i;
for (i = 0; i < EVP_MAX_KEY_LENGTH; i++) {
sscanf(key_str + 2 * i, "%2hhx", &key[i]);
}

// Initialize OpenSSL library
ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();

// Generate RSA key pair
RSA* rsa = RSA_new();
BIGNUM* exponent = BN_new();
BN_set_word(exponent, RSA_F4);
RSA_generate_key_ex(rsa, 2048, exponent, NULL);

// Hash message
EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();
if (hash_ctx == NULL) {
fprintf(stderr, "Error allocating hash context\n");
return 1;
}
EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL);
EVP_DigestUpdate(hash_ctx, message, strlen(message));

unsigned char hash[EVP_MAX_MD_SIZE];
unsigned int hash_len;
EVP_DigestFinal_ex(hash_ctx, hash, &hash_len);

// Encrypt hash with private key
int rsa_len = RSA_size(rsa);
unsigned char encrypted_hash[rsa_len];
int encrypted_len = RSA_private_encrypt(hash_len, hash, encrypted_hash, rsa, RSA_PKCS1_PADDING);
if (encrypted_len == -1) {
fprintf(stderr, "Error encrypting hash\n");
return 1;
}

// Set up cipher context for AES in CBC mode
EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
if (cipher_ctx == NULL) {
fprintf(stderr, "Error allocating cipher context\n");
return 1;
}
EVP_EncryptInit_ex(cipher_ctx, EVP_aes_128_cbc(), NULL, key, NULL);

// Determine length of encrypted message
EVP_EncryptUpdate(cipher_ctx, NULL, &encrypted_len, message, strlen(message));
encrypted_len += EVP_CIPHER_CTX_block_size(cipher_ctx);

// Allocate buffer for encrypted message
unsigned char* encrypted_message = malloc(encrypted_len);
if (encrypted_message == NULL) {
fprintf(stderr, "Error allocating buffer for encrypted message\n");
return 1;
}

// Encrypt message
int len;
EVP_EncryptUpdate(cipher_ctx, encrypted_message, &len, message, strlen(message));
encrypted_len = len;
EVP_EncryptFinal_ex(cipher_ctx, encrypted_message + len, &len);
encrypted_len += len;

// Concatenate encrypted hash and encrypted message
unsigned char* signature = malloc(rsa_len + encrypted_len);
if (signature == NULL) {
fprintf(stderr, "Error allocating buffer for signature\n");
return 1;
}
memcpy(signature, encrypted_hash, rsa_len);
memcpy(signature + rsa_len, encrypted_message, encrypted_len);

// Send signature to recipient
printf("Encrypted hash:\n");
for (i = 0; i < encrypted_len; i++) {
printf("%02x", encrypted_hash[i]);
}
printf("\n");

printf("Encrypted message:\n");
for (i = 0; i < encrypted_len; i++) {
printf("%02x", encrypted_message[i]);
}
printf("\n");

// Clean up
free(encrypted_message);
free(signature);
EVP_MD_CTX_free(hash_ctx);
EVP_CIPHER_CTX_free(cipher_ctx);
BN_free(exponent);
RSA_free(rsa);
EVP_cleanup();
ERR_free_strings();

return 0;
}