#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

int sign_message(unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len){
    int result = 0;

    RSA *private_key = NULL;
    BIO *keybio = NULL;

    // Read the private key from a file
    keybio = BIO_new_file("private.pem", "r");
    if (!keybio){
        fprintf(stderr, "Error reading private key file\n");
        return 0;
    }

    // Load the private key
    private_key = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    if (!private_key){
        fprintf(stderr, "Error loading private key\n");
        return 0;
    }

    // Allocate memory for the signature
    *sig = malloc(RSA_size(private_key));
    if (!*sig){
        fprintf(stderr, "Error allocating memory for signature\n");
        return 0;
    }

    // Sign the message
    if (RSA_sign(NID_sha256, msg, msg_len, *sig, sig_len, private_key) != 1){
        fprintf(stderr, "Error signing message\n");
        ERR_print_errors_fp(stderr);
        result = 0;
    }
    else{
        result = 1;
    }

    RSA_free(private_key);
    BIO_free(keybio);

    return result;
}


int verify_signature(unsigned char *msg, size_t msg_len, unsigned char *sig, size_t sig_len){
    int result = 0;

    RSA *public_key = NULL;
    BIO *keybio = NULL;

    // Read the public key from a file
    keybio = BIO_new_file("public.pem", "r");
    if (!keybio){
        fprintf(stderr, "Error reading public key file\n");
        return 0;
    }

    // Load the public key
    public_key = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
    if (!public_key){
        fprintf(stderr, "Error loading public key\n");
        return 0;
    }

    // Verify the signature
    if (RSA_verify(NID_sha256, msg, msg_len, sig, sig_len, public_key) != 1){
        fprintf(stderr, "Error verifying signature\n");
        ERR_print_errors_fp(stderr);
        result = 0;
    }
    else{
        result = 1;
    }

    RSA_free(public_key);
    BIO_free(keybio);

    return result;
}

