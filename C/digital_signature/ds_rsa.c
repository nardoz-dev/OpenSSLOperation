#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

int main(int argc, char** argv)
{
    int ret = 0;

    // Generate a new RSA key pair
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if(!rsa)
        return -1;
        
    // Extract the public and private keys
    const BIGNUM* n = NULL;
    const BIGNUM* e = NULL;
    const BIGNUM* d = NULL;
    RSA_get0_key(rsa, &n, &e, &d);
    BIGNUM* n_copy = BN_dup(n);
    BIGNUM* e_copy = BN_dup(e);
    RSA* public_rsa = RSA_new();
    RSA_set0_key(public_rsa, n_copy, e_copy, NULL);
    RSA* private_rsa = RSA_new();
    RSA_set0_key(private_rsa, n_copy, e_copy, BN_dup(d));

    // Sign a message
    const char* message = "Hello, World!";
    unsigned char message_digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, strlen(message));
    SHA256_Final(message_digest, &sha256);
    unsigned char signature[RSA_size(private_rsa)];
    unsigned int signature_len = 0;
    if (RSA_sign(NID_sha256, message_digest, SHA256_DIGEST_LENGTH, signature, &signature_len, private_rsa) != 1) {
        return -1;
    }

    // Verify the signature
    if (RSA_verify(NID_sha256, message_digest, SHA256_DIGEST_LENGTH, signature, signature_len, public_rsa) != 1) {
        return -1;
    }
    else {
        printf("Signature verification successful!\n");
    }

    return 0;
}
