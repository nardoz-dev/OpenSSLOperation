#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

int main(int argc, char** argv)
{
    int ret = 0;

    // Generate a new ECDSA key pair
    EC_KEY* ecdsa = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecdsa) {
        ret = -1;
        goto err;
    }
    if (EC_KEY_generate_key(ecdsa) != 1) {
        ret = -1;
        goto err;
    }

    // Extract the public and private keys
    const EC_GROUP* group = EC_KEY_get0_group(ecdsa);
    const EC_POINT* public_key = EC_KEY_get0_public_key(ecdsa);
    const BIGNUM* private_key = EC_KEY_get0_private_key(ecdsa);
    EC_KEY* public_ecdsa = EC_KEY_new();
    EC_KEY_set_group(public_ecdsa, group);
    EC_KEY_set_public_key(public_ecdsa, public_key);
    EC_KEY* private_ecdsa = EC_KEY_new();
    EC_KEY_set_group(private_ecdsa, group);
    EC_KEY_set_private_key(private_ecdsa, private_key);

    // Sign a message
    const char* message = "Hello, World!";
    unsigned char message_digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, strlen(message));
    SHA256_Final(message_digest, &sha256);
    ECDSA_SIG* signature = ECDSA_do_sign(message_digest, SHA256_DIGEST_LENGTH, private_ecdsa);
    if (!signature) {
        ret = -1;
        goto err;
    }

    // Verify the signature
    if (ECDSA_do_verify(message_digest, SHA256_DIGEST_LENGTH, signature, public_ecdsa) != 1) {
        ret = -1;
        goto err;
    }

    printf("Signature verification successful!\n");

err:
    // Clean up
    ECDSA_SIG_free(signature);
    EC_KEY_free(private_ecdsa);
    EC_KEY_free(public_ecdsa);
    EC_KEY_free(ecdsa);
    return ret;
}

