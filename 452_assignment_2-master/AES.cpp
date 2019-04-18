#include "AES.h"

/**
 * Sets the key to use
 * @param key - the first byte of this represents whether
 * to encrypt or to decrypt. 00 means encrypt and any other
 * value to decrypt.  Then come the bytes of the 128-bit key
 * (should be 16 of them).
 * @return - True if the key is valid and False otherwise
 */
bool AES::setKey(const unsigned char* keyArray)
{
    
    // TODO: AES implementation of openssl cares about whether
    // you are encrypting or decrypting when setting the key.
    // That is, when encrypting you use function AES_set_encrypt_key(...)
    // and when decrypting AES_set_decrypt_key(...).
    //
    // One way to solve this problem is to pass in a 17 byte key, where
    // the first byte is used to indicate whether we are encrypting or
    // decrypting. E.g., if the first byte is 0, then use AES_set_encrypt_key(...).
    // Otherwise, use AES_set_decrypt_key(...).  The rest of the bytes in the
    // array indicate the 16 bytes of the 128-bit AES key.
    //
    // Both functions return 0 on success and other values on faliure.
    // For documentation, please see https://boringssl.googlesource.com/boringssl/+/2623/include/openssl/aes.h
    // and aes.cpp example provided with the assignment.
    if (strlen((char*)(keyArray)) != 17)
    {
        fprintf(stderr, "ERROR [%s %s %d]: Invalid length of key.\n",
                __FILE__, __FUNCTION__, __LINE__);
        return false;
    }
    
    //copy the keyarray to key
    //for (i = )
    
    unsigned char* key = new unsigned char[16];
    //strncpy(key,((char*)keyArray)+1, 16);
    for (int i =1; i < 17; i++){
        key[i - 1] = keyArray[i];
    }
    if (keyArray[0] == '0')
    {
        if (AES_set_encrypt_key(key, 128, &this ->enc_key) !=0){
            fprintf(stderr, "ERROR [%s %s %d]: encrypt key has failed!.\n");
            return false;
        }
        fprintf(stderr, "encrypt key has succeeded!.\n");
        return true;
    }
    else if (keyArray[0] == '1')
    {
        if (AES_set_encrypt_key(key, 128, &this ->dec_key) !=0){
            fprintf(stderr, "ERROR [%s %s %d]: decrypt key has failed!.\n");
            return false;
        }
        fprintf(stderr, "decrypt key has succeeded!.\n");
        return true;
    }
    else
    {
        fprintf(stderr, "ERROR [%s %s %d]: Invalid key!.\n");
        return false;
    }
    
    
    //return false;
    
}

/**
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
unsigned char* AES::encrypt(const unsigned char* plainText)
{
    
    //TODO: 1. Dynamically allocate a block to store the ciphertext.
    unsigned char* e_result = new unsigned char [16];
    //    2. Use AES_ecb_encrypt(...) to encrypt the text (please see the URL in setKey(...)
    //    and the aes.cpp example provided.
    //memset(e_result, 0, 17);
    AES_ecb_encrypt(plainText, e_result, &this->enc_key, AES_ENCRYPT);
    //     3. Return the pointer to the ciphertext
    return e_result;
    
    //return NULL
}

/**
 * Decrypts a string of ciphertext
 * @param cipherText - the ciphertext
 * @return - the plaintext
 */
unsigned char* AES::decrypt(const unsigned char* cipherText)
{
    
    //TODO: 1. Dynamically allocate a block to store the plaintext.
    unsigned char* d_result = new unsigned char [17];
    //    2. Use AES_ecb_encrypt(...) to decrypt the text (please see the URL in setKey(...)
    //    and the aes.cpp example provided.
    //memset(d_result,0 ,17);
    AES_ecb_encrypt(cipherText, d_result, &this->dec_key, AES_DECRYPT);
    //     3. Return the pointer to the plaintext
    return d_result;
    
    
    //return NULL;
}
