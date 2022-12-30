
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

EVP_PKEY* get_private_key(){
    // Read the private key from a file
    FILE *fp = fopen("private.pem", "rb");
    if (!fp) {
        fprintf(stderr, "Error opening private key file\n");
        return NULL;
    }

    // Load the private key into an EVP_PKEY structure
    EVP_PKEY *private_key = 1234;
    /*PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!private_key) {
        fprintf(stderr, "Error reading private key\n");
        fclose(fp);
        return NULL;
    }*/

    fclose(fp);
    return private_key;
}




int main(int argc, char *argv[])
{
    // Input message to be encrypted
    unsigned char input[] = "Hello, World!";

    // Secret key for the symmetric encryption
    unsigned char secret_key[] = "MySecretKey";
    char *key = secret_key;

    // Initialization vector (IV) for the symmetric encryption
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};

    // Buffer for the encrypted message
    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;
    // Allocate memory for the ciphertext
    ciphertext = (unsigned char*)malloc(strlen(input) + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext) {
        fprintf(stderr, "Error allocating memory for ciphertext\n");
        return 1;
    }

    // Encrypt the message using AES in CBC mode
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, secret_key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, input, strlen(input));
    int final_len;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ciphertext_len += final_len;

    // Sign the message using RSA
    EVP_PKEY *private_key = get_private_key();
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_SignInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_SignUpdate(mdctx, input, strlen(input));
    unsigned char *signature = NULL;
    size_t signature_len = strlen(signature);
    EVP_SignFinal(mdctx, signature, &signature_len, private_key);

    // Send the encrypted message and signature to the recipient
    //send_to_recipient(ciphertext, ciphertext_len, signature, signature_len);
   // printf("signature : \n %c", signature);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    EVP_MD_CTX_destroy(mdctx);
    free(ciphertext);
    EVP_PKEY_free(private_key);

    return 0;
}
