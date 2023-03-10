#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

// Encrypts the plaintext using AES-CBC with the given key and iv
// Returns the ciphertext as a newly allocated buffer (which should be freed by the caller)
// Returns NULL on error
unsigned char *aes_cbc_encrypt(const unsigned char *plaintext, int plaintext_len,
                               const unsigned char *key, const unsigned char *iv,
                               int *ciphertext_len);

// Decrypts the ciphertext using AES-CBC with the given key and iv
// Returns the plaintext as a newly allocated buffer (which should be freed by the caller)
// Returns NULL on error
unsigned char *aes_cbc_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                               const unsigned char *key, const unsigned char *iv,
                               int *plaintext_len);

unsigned char *aes_cbc_encrypt(const unsigned char *plaintext, int plaintext_len,
                            const unsigned char *key, const unsigned char *iv,
                            int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    unsigned char *ciphertext;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
      return NULL;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Allocate memory for the ciphertext
    ciphertext = malloc(plaintext_len + EVP_CIPHER_CTX_block_size(ctx));
    if (!ciphertext) {
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len) != 1 ) {
      EVP_CIPHER_CTX_free(ctx);
      free(ciphertext);
      return NULL;
    }
    int len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertext_len, &len) != 1 ) {
      EVP_CIPHER_CTX_free(ctx);
      free(ciphertext);
      return NULL;
    }
    *ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

unsigned char *aes_cbc_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                            const unsigned char *key, const unsigned char *iv,
                            int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    unsigned char *plaintext;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
      return NULL;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      return NULL;
    }

    // Allocate memory for the plaintext
    plaintext = malloc(ciphertext_len + EVP_CIPHER_CTX_block_size(ctx));
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return NULL;
    }
    int len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + *plaintext_len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return NULL;
    }
    *plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}



int main(int argc, char *argv[]) {
  // Set the key and iv    =>  For real application we need to use a secure method of generating a random key and iv.
  unsigned char key[32] = {0};
  unsigned char iv[16] = {0};

  // Set the plaintext
  unsigned char *plaintext = (unsigned char *)"Hello, world!";
  int plaintext_len = strlen((char *)plaintext);

  // Encrypt the plaintext
  int ciphertext_len;
  unsigned char *ciphertext = aes_cbc_encrypt(plaintext, plaintext_len, key, iv, &ciphertext_len);
  if (!ciphertext) {
    printf("Error encrypting the plaintext\n");
    return 1;
  }

  // Decrypt the ciphertext
  int decrypted_len;
  unsigned char *decrypted = aes_cbc_decrypt(ciphertext, ciphertext_len, key, iv, &decrypted_len);
  if (!decrypted) {
    printf("Error decrypting the ciphertext\n");
    free(ciphertext);
    return 1;
  }

  // Print the plaintext and decrypted data
  printf("Plaintext: %s\n", plaintext);
  printf("Decrypted: %s\n", decrypted);

  // Clean up
  free(ciphertext);
  free(decrypted);

  return 0;
}
