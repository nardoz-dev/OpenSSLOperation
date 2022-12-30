#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

int main(int argc, char *argv[])
{
    // Generate a new RSA key pair
    RSA *keypair = RSA_generate_key(2048, 65537, NULL, NULL);

    // Get the private key from the key pair
    EVP_PKEY *private_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(private_key, keypair);

    // Get the public key from the key pair
    EVP_PKEY *public_key = EVP_PKEY_new();
    RSA *rsa = RSAPublicKey_dup(keypair);
    EVP_PKEY_assign_RSA(public_key, rsa);

    // Input message to be encrypted and signed
    unsigned char input[] = "Hello, World!";

    // Buffer for the encrypted message
    unsigned char *ciphertext = NULL;

    // Buffer for the digital signature
    unsigned char *signature = NULL;

    // Initialization vector (IV) for the symmetric encryption
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};

    // Encrypt the message using AES in CBC mode
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, iv);
    int ciphertext_len;
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, input, strlen(input));
    int final_len;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ciphertext_len += final_len;

    // Sign the message using SHA-256
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_SignInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_SignUpdate(mdctx, input, strlen(input));
    size_t signature_len;
    EVP_SignFinal(mdctx, signature, &signature_len, private_key);

    // Send the encrypted message and signature to the recipient

    // Buffer for the encrypted key envelope
    unsigned char *key_envelope = NULL;

    // Encrypt the secret key using the recipient's public key
    EVP_CIPHER_CTX *key_ctx;
    key_ctx = EVP_CIPHER_CTX_new();
    EVP_SealInit(key_ctx, EVP_aes_256_cbc(), &key_envelope, &key_envelope_len, iv, &public_key, 1);
    EVP_SealUpdate(key_ctx, key_envelope, &key_envelope_len, secret_key, strlen(secret_key));
    EVP_SealFinal(key_ctx, key_envelope + key_envelope_len, &final_len);
    key_envelope_len += final_len;

    // Send the encrypted message, key envelope, and signature to the recipient
    send_to_recipient(ciphertext, ciphertext_len, key_envelope, key_envelope_len, signature, signature_len);

    // Clean up
    EVP_CIPHER_CTX_free(key_ctx);
    EVP_MD_CTX_destroy(mdctx);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);

    return 0;
}