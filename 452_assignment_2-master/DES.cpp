#include "DES.h"

/**
 * Sets the key to use
 * @param key - the key to use
 * @return - True if the key is valid and False otherwise
 */
bool DES::setKey(const unsigned char* keyArray)
{
     cout << "keyArray " << keyArray << endl;
	/**
	 * First let's covert the char string
	 * into an integer byte string
	 */
	// cout << "keyArray " << keyArray << endl;
	
	/* The key error code */
	int keyErrorCode = -1;

	/* A single byte */
	unsigned char singleByte = 0;	
	
	/* The key index */
	int keyIndex = 0;
	
	/* The DES key index */
	int desKeyIndex = 0;
		
	/* Go through the entire key character by character */
	while(desKeyIndex != 8)
	{
		/* Convert the key if the character is valid */
		if((this->des_key[desKeyIndex] = twoCharToHexByte(keyArray + keyIndex)) == 'z') {
            cout << "setKey returning false " << endl;
			return false;
        }
		
                        // cout << "current key " << keyArray + keyIndex << endl;
		/* Go to the second pair of characters */
		keyIndex += 2;	
		
		/* Increment the index */
		++desKeyIndex;
	}
	
	fprintf(stdout, "DES KEY: ");
	
	/* Print the key */
	for(keyIndex = 0; keyIndex < 8; ++keyIndex){
		cout << this->des_key[keyIndex] << endl;
    }
    // cout << this->des_key << endl;
	
	fprintf(stdout, "\n");	
	
	
	/* Set the encryption key */
	if ((keyErrorCode = DES_set_key_checked(&this->des_key, &this->key)) != 0)
	{
		fprintf(stderr, "\nkey error %d\n", keyErrorCode);
		
		return false;
	}
	
	/* All is well */	
	return true;
}

/**	
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
unsigned char* DES::encrypt(const unsigned char* plaintext)
{
	//1. Check to make sure that the block is exactly 8 characters (i.e. 64 bits)
    unsigned char * returnCipherText = new unsigned char [DES_BLOCK_SIZE];
    unsigned char * firstHalf = new unsigned char[4];
    unsigned char * secondHalf = new unsigned char[4];
    DES_LONG block[2];
  
    for (int i=0; i < 4; ++i ) {
            firstHalf[i] = plaintext[i + 0];
            secondHalf[i] = plaintext[i + 4];
        }

    // cout << "firstHalf: " << firstHalf << endl;
    // cout << "secondHalf: " << secondHalf << endl;
    //3. Use ctol() to convert the first 4 chars into long; store the result in block[0]
    block[0] = ctol(firstHalf);
    //4. Use ctol() to convert the second 4 chars into long; store the resul in block[1]
	block[1] = ctol(secondHalf);
    //5. Perform des_encrypt1 in order to encrypt the block using this->key (see sample codes for details)
    DES_encrypt1(block, &this->key, ENC);
    //6. Convert the first ciphertext long to 4 characters using ltoc()

    // cout << returnCipherText << endl;
	ltoc(block[0], returnCipherText);
    // cout << returnCipherText << endl;
    //7. Convert the second ciphertext long to 4 characters using ltoc()
	ltoc(block[1], returnCipherText + 4);
    // cout << returnCipherText << endl;
    //8. Save the results in the the dynamically allocated char array 
    // (e.g. unsigned char* bytes = nerw unsigned char[8]).

	//9. Return the pointer to the dynamically allocated array.
    // delete [] firstHalf;
    // delete [] secondHalf;

	return returnCipherText;
}

/**
 * Decrypts a string of ciphertext
 * @param ciphertext - the ciphertext
 * @return - the plaintext
 */
unsigned char* DES::decrypt(const unsigned char* ciphertext)
{

	//LOGIC:
	// Same logic as encrypt(), except in step 5. decrypt instead of encrypting
    //1. Check to make sure that the block is exactly 8 characters (i.e. 64 bits)
    unsigned char * returnPlaintext = new unsigned char [DES_BLOCK_SIZE];
    unsigned char * firstHalf = new unsigned char[4];
    unsigned char * secondHalf = new unsigned char[4];
    DES_LONG block[2];


    for (int i=0; i < 4; ++i ) {
            firstHalf[i] = ciphertext[i + 0];
            secondHalf[i] = ciphertext[i + 4];
        }
        
    
    
    //3. Use ctol() to convert the first 4 chars into long; store the result in block[0]
    block[0] = ctol(firstHalf);
    //4. Use ctol() to convert the second 4 chars into long; store the resul in block[1]
    block[1] = ctol(secondHalf);
    //5. Perform des_encrypt1 in order to encrypt the block using this->key (see sample codes for details)
    DES_encrypt1(block, &this->key, DEC);
    //6. Convert the first ciphertext long to 4 characters using ltoc()

    ltoc(block[0], returnPlaintext);
    //7. Convert the second ciphertext long to 4 characters using ltoc()
    ltoc(block[1], returnPlaintext + 4);
    //8. Save the results in the the dynamically allocated char array 
    // (e.g. unsigned char* bytes = nerw unsigned char[8]).

    //9. Return the pointer to the dynamically allocated array.
    // delete [] firstHalf;
    // delete [] secondHalf;

    return returnPlaintext;
}

/**
 * Converts an array of 8 characters
 * (i.e. 4 bytes/32 bits)
 * @param c - the array of 4 characters (i.e. 1-byte per/character
 * @return - the long integer (32 bits) where each byte
 * is equivalent to one of the bytes in a character array
 */
DES_LONG DES::ctol(unsigned char *c) 
{
        /* The long integer */
	DES_LONG l;
        
	l =((DES_LONG)(*((c)++)));
        l = l | (((DES_LONG)(*((c)++)))<<8L);
        l = l | (((DES_LONG)(*((c)++)))<<16L);
        l = l | (((DES_LONG)(*((c)++)))<<24L);
        return l;
};


/** 
 * Converts a long integer (4 bytes = 32 bits)
 * into an array of 8 characters.
 * @param l - the long integer to convert
 * @param c - the character array to store the result
 */
void DES::ltoc(DES_LONG l, unsigned char *c) 
{
        *((c)++)=(unsigned char)(l&0xff);
        *((c)++)=(unsigned char)(((l)>> 8L)&0xff);
        *((c)++)=(unsigned char)(((l)>>16L)&0xff);
        *((c)++)=(unsigned char)(((l)>>24L)&0xff);
}

/**
 * Converts a character into a hexidecimal integer
 * @param character - the character to convert
 * @return - the converted character, or 'z' on error
 */
unsigned char DES::charToHex(const char& character)
{
	/* Is the first digit 0-9 ? */	
	if(character >= '0' && character <= '9') {
        // cout << "if(character >= '0' && character <= '9') true, char = " << character << endl;	
		/* Convert the character to hex */
        // cout << "Convert the character to hex, character - '0' normal = " << character - '0' << endl;  
        // cout << ios::hex << "Convert the character to hex, character - '0' hex = " << character - '0' << endl; 
		return character - '0';
    }
	/* It the first digit a letter 'a' - 'f'? */
	else if(character >= 'a' && character <= 'f') {
		// /* Conver the cgaracter to hex */
  //       cout << "Convert the character to hex, (character - 97) + 10 " << (character - 97) + 10 << endl;  
  //       cout << ios::hex << "Convert the character to hex, (character - 97) + 10  hex = " << (character - 97) + 10 << endl; 
		return (character - 97) + 10;	
    }
	/* Invalid character */
	else return 'z';
}

/**
 * Converts two characters into a hex integers
 * and then inserts the integers into the higher
 * and lower bits of the byte
 * @param twoChars - two charcters representing the
 * the hexidecimal nibbles of the byte.
 * @param twoChars - the two characters
 * @return - the byte containing having the
 * valud of two characters e.g. string "ab"
 * becomes hexidecimal integer 0xab.
 */
unsigned char DES::twoCharToHexByte(const unsigned char* twoChars)
{
	/* The byte */
	unsigned char singleByte;
	
	/* The second character */
	unsigned char secondChar;

	/* Convert the first character */
	if((singleByte = charToHex(twoChars[0])) == 'z') 
	{
		/* Invalid digit */
		return 'z';
	}
	
	/* Move the newly inserted nibble from the
	 * lower to upper nibble.
	 */
	singleByte = (singleByte << 4);
	
	/* Conver the second character */
	if((secondChar = charToHex(twoChars[1])) == 'z')
		return 'z'; 
	
	/* Insert the second value into the lower nibble */	
	singleByte |= secondChar;

	return singleByte;
}


