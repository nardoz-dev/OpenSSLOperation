#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/blowfish.h>

#define BLOCK_SIZE 8

int main(int argc, char *argv[]){
    // For real application we need to use a secure method of generating a random key and iv.
    char *key = "1838";
    int key_len = strlen(key);
    if (key_len < 4 || key_len > 56) {
        fprintf(stderr, "Error: key must be between 4 and 56 bytes\n");
        return 1;
    }

    char *message = "Private!";
    int message_len = strlen(message);
    // Create a Blowfish context
    BF_KEY bf_key;
    BF_set_key(&bf_key, key_len, (unsigned char*)key);

    // Add padding to the message to ensure that it is an integer multiple of the block size (Need a length multiple of the block size 8bytes)
    int padded_len = (message_len + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
    unsigned char *padded_message = calloc(padded_len, 1);
    memcpy(padded_message, message, message_len);


    // Allocate memory for the encrypted message
    unsigned char *encrypted_message = malloc(padded_len + BLOCK_SIZE);
    if (encrypted_message == NULL) {
        perror("malloc");
        return 1;
    }

    // Encrypt the message
    BF_ecb_encrypt(padded_message, encrypted_message, &bf_key, BF_ENCRYPT);

    // The encrypted message will be at least one block (8 bytes) larger than the padded message
    int encrypted_len = padded_len + BLOCK_SIZE;
    printf("Original message: %s\n", message);
    // Print the encrypted message
    printf("Encrypted message: ");
    for (int i = 0; i < encrypted_len + BLOCK_SIZE; i++) {
        printf("%02x", encrypted_message[i]);
    }
    printf("\n");

    // Allocate memory for the decrypted message
    unsigned char *decrypted_message = malloc(encrypted_len);
    if (decrypted_message == NULL) {
        perror("malloc");
        return 1;
    }

    // Decrypt the message
    BF_ecb_encrypt(encrypted_message, decrypted_message, &bf_key, BF_DECRYPT);

    // Print the decrypted message
    printf("Decrypted message: %s\n", decrypted_message);

    // Free the allocated memory
    free(padded_message);
    free(encrypted_message);
    free(decrypted_message);


    return 0;
}