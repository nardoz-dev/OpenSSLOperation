#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/aes.h>

// Create digital signature with RSA and AES in CBC mode
int create_signature(const char* message, const unsigned char* key, const char* exponent_str, const char* modulus_str) {
// Initialize OpenSSL library
ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();

// Convert exponent and modulus from hexadecimal string to BIGNUM
BIGNUM* exponent = BN_new();
BN_hex2bn(&exponent, exponent_str);
BIGNUM* modulus = BN_new();
BN_hex2bn(&modulus, modulus_str);

// Set up RSA context
RSA* rsa = RSA_new();
if (rsa == NULL) {
fprintf(stderr, "Error allocating RSA context\n");
return 1;
}
RSA_set0_key(rsa, modulus, exponent, NULL);

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

// Encrypt hash
int rsa_len = RSA_size(rsa);
unsigned char encrypted_hash[rsa_len];
if (RSA_private_encrypt(hash_len, hash, encrypted_hash, rsa, RSA_PKCS1_OAEP_PADDING) == -1) {
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

// Encrypt message
int encrypted_len = strlen(message) + EVP_CIPHER_CTX_block_size(cipher_ctx);
unsigned char* encrypted_message = malloc(encrypted_len);
if (encrypted_message == NULL) {
fprintf(stderr, "Error allocating encrypted message buffer\n");
return 1;
}
int tmp_len;
if (EVP_EncryptUpdate(cipher_ctx, encrypted_message, &tmp_len, (unsigned char*) message, strlen(message)) == 0) {
fprintf(stderr, "Error encrypting message\n");
return 1;
}
encrypted_len = tmp_len;
if (EVP_EncryptFinal_ex(cipher_ctx, encrypted_message + encrypted_len, &tmp_len) == 0) {
fprintf(stderr, "Error encrypting message\n");
return 1;
}
encrypted_len += tmp_len;

// Concatenate encrypted hash and encrypted message
unsigned char* signature = malloc(rsa_len + encrypted_len);
if (signature == NULL) {
fprintf(stderr, "Error allocating signature buffer\n");
return 1;
}
memcpy(signature, encrypted_hash, rsa_len);
memcpy(signature + rsa_len, encrypted_message, encrypted_len);

// Clean up
free(encrypted_message);
EVP_MD_CTX_free(hash_ctx);
EVP_CIPHER_CTX_free(cipher_ctx);
BN_free(exponent);
RSA_free(rsa);

// Print signature to stdout as hexadecimal string
int i;
for (i = 0; i < rsa_len + encrypted_len; i++) {
printf("%02x", signature[i]);
}
putchar('\n');

// Clean up
free(signature);

// Shut down OpenSSL library
EVP_cleanup();
ERR_free_strings();

return 0;
}

int verify_signature(unsigned char* signature, int signature_len, unsigned char* key, const char* exponent, const char* modulus) {
// Initialize OpenSSL
ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();
OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

// Convert exponent and modulus from hexadecimal string to BIGNUM
BIGNUM* e = BN_new();
BIGNUM* n = BN_new();
BN_hex2bn(&e, exponent);
BN_hex2bn(&n, modulus);

// Initialize RSA context
RSA* rsa = RSA_new();
if(rsa == NULL ) {
    printf("PORCODIO");
    //rsa->e = e;
    //rsa->en = n;
}


// Decrypt signature
unsigned char* decrypted_signature = malloc(RSA_size(rsa));
if (decrypted_signature == NULL) {
fprintf(stderr, "Error allocating decrypted signature buffer\n");
return 1;
}
if (RSA_private_decrypt(signature_len, signature, decrypted_signature, rsa, RSA_PKCS1_OAEP_PADDING) < 0) {
fprintf(stderr, "Error decrypting signature: %s\n", ERR_error_string(ERR_get_error(), NULL));
return 1;
}

// Extract message and hash from decrypted signature
unsigned char* message = malloc(signature_len - 16);
if (message == NULL) {
fprintf(stderr, "Error allocating message buffer\n");
return 1;
}
memcpy(message, decrypted_signature, signature_len - 16);
unsigned char* hash = malloc(16);
if (hash == NULL) {
fprintf(stderr, "Error allocating hash buffer\n");
return 1;
}
memcpy(hash, decrypted_signature + signature_len - 16, 16);

// Initialize AES context
AES_KEY aes_key;
if (AES_set_decrypt_key(key, 128, &aes_key) != 0) {
fprintf(stderr, "Error setting AES key: %s\n", ERR_error_string(ERR_get_error(), NULL));
return 1;
}

// Decrypt message
unsigned char* decrypted_message = malloc(signature_len - 16);
if (decrypted_message == NULL) {
fprintf(stderr, "Error allocating decrypted message buffer\n");
return 1;
}
AES_cbc_encrypt(message, decrypted_message, signature_len - 16, &aes_key, hash, AES_DECRYPT);

// Verify hash
unsigned char* calculated_hash = malloc(16);
if (calculated_hash == NULL) {
fprintf(stderr, "Error allocating calculated hash buffer\n");
return 1;
}
SHA1(decrypted_message, signature_len - 16, calculated_hash);
if (memcmp(hash, calculated_hash, 16) != 0) {
fprintf(stderr, "Error: invalid signature\n");
return 1;
}

// Print message
printf("%s\n", decrypted_message);

// Clean up
RSA_free(rsa);
free(decrypted_signature);
free(message);
free(hash);
free(decrypted_message);
free(calculated_hash);

return 0;
}

int main(int argc, char** argv) {
    // Parse command line arguments
    if (argc < 3) {
        fprintf(stderr, "Usage: %s create|verify ...\n", argv[0]);
        return 1;
    }
    const char* command = argv[1];

    // Create or verify signature
    if (strcmp(command, "create") == 0) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s create <key> <message>\n", argv[0]);
        return 1;
    }
    const char* key_str = argv[2];
    unsigned char key[16];
    int i;
    for (i = 0; i < 16; i++) {
        char byte_str[3] = {key_str[2*i], key_str[2*i + 1], '\0'};
        key[i] = (unsigned char)strtol(byte_str, NULL, 16);
    }
    const char* message = argv[3];
    } else if (strcmp(command, "verify") == 0) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s verify <signature> <key> <exponent> <modulus>\n", argv[0]);
        return 1;
    }
    const char* signature_str = argv[2];
    int signature_len = strlen(signature_str);
    if (signature_len % 2 != 0) {
        fprintf(stderr, "Error: invalid signature\n");
        return 1;
    }
    signature_len /= 2;
    unsigned char* signature = malloc(signature_len);
    if (signature == NULL) {
        fprintf(stderr, "Error allocating signature buffer\n");
        return 1;
    }
    int i;
    for (i = 0; i < signature_len; i++) {
        char byte_str[3] = {signature_str[2*i], signature_str[2*i + 1], '\0'};
        signature[i] = (unsigned char)strtol(byte_str, NULL, 16);
    }
    const char* key_str = argv[3];
    unsigned char key[16];
    if (strlen(key_str) != 32) {
        fprintf(stderr, "Error: invalid key\n");
        return 1;
    }
    for (i = 0; i < 16; i++) {
         char byte_str[3] = {key_str[2*i], key_str[2*i + 1], '\0'};
      key[i] = (unsigned char)strtol(byte_str, NULL, 16);
    }
    const char* exponent = argv[4];
    const char* modulus = argv[5];
    return verify_signature(signature, signature_len, key, exponent, modulus);
  } else {
    fprintf(stderr, "Error: invalid command\n");
    return 1;
  }
}