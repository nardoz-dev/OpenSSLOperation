#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>

/*
This example generates an RSA key pair with a key length of 2048 bits and a public exponent of RSA_F4 (0x10001). 
It then writes the private key to a file named "private.pem" and the public key to a file named "public.pem", both in PEM format.

To generate the key pair, the example calls RSA_generate_key from the OpenSSL library.
To write the keys to files, it uses the BIO functions from OpenSSL, which provide a flexible interface for reading and writing data in various formats.

Note that this is just a simple example to illustrate the basic steps involved in generating an RSA key pair. 
In a real application, you may want to handle errors more gracefully and consider additional security measures, 
such as setting secure permissions on the key files and protecting the private key with a passphrase.

*/


int generate_key_pair(char *private_key_file, char *public_key_file){
    int result = 0;

    RSA *keypair = NULL;
    BIO *private_key_bio = NULL;
    BIO *public_key_bio = NULL;

    // Generate the key pair
    keypair = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!keypair){
        fprintf(stderr, "Error generating key pair\n");
        return 0;
    }

    // Write the private key to a file
    private_key_bio = BIO_new_file(private_key_file, "w");
    if (!private_key_bio){
        fprintf(stderr, "Error creating private key file\n");
        return 0;
    }
    if (PEM_write_bio_RSAPrivateKey(private_key_bio, keypair, NULL, NULL, 0, NULL, NULL) != 1){
        fprintf(stderr, "Error writing private key\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Write the public key to a file
    public_key_bio = BIO_new_file(public_key_file, "w");
    if (!public_key_bio){
        fprintf(stderr, "Error creating public key file\n");
        return 0;
    }
    if (PEM_write_bio_RSA_PUBKEY(public_key_bio, keypair) != 1){
        fprintf(stderr, "Error writing public key\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    result = 1;

    RSA_free(keypair);
    BIO_free(private_key_bio);
    BIO_free(public_key_bio);

    return result;
}
