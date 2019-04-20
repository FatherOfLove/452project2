#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <openssl/des.h>
#include "CipherInterface.h"
#include "DES.h"
#include "AES.h"
using namespace std;
#define DES_KEY_LENGTH 16
#define AES_KEY_LENGTH 17

int main(int argc, char** argv)
{
	int mainTraceIterator = 1;
	/**
	 * TODO: Replace the code below	with your code which can SWITCH
	 * between DES and AES and encrypt files. DO NOT FORGET TO PAD
	 * THE LAST BLOCK IF NECESSARY.
	 *
	 * NOTE: due to the incomplete skeleton, the code may crash or
	 * misbehave.
	 */


	string cipherType = argv[1];

	char * cipherKeyString = argv[2];
	string cipherKeyStringSpiteCpp = argv[2];
	string encodingType = argv[3];
	char * inputFileName = argv[4];
	char * outputFileName = argv[5];

	unsigned char * honestCipher = reinterpret_cast<unsigned char*>(argv[2]);
	cout << "honestCipher" << honestCipher << endl;
	unsigned int cipherKeyLength = cipherKeyStringSpiteCpp.length();
	unsigned char cipherKey [cipherKeyLength];
	unsigned int blockSize = 0;




	CipherInterface* cipher = NULL;

	// Check if all arguments are present
	if (!outputFileName || !inputFileName) {
		fprintf(stderr, "ERROR [%s %s %d]: Missing arguments\n",
		__FILE__, __FUNCTION__, __LINE__);
		exit(-1);
	}


		// check key length
	for (int i = 0; i < cipherKeyLength; ++i) {
			cipherKey[i] = cipherKeyString[i];
						// if (cipherKeyLength == 16) cipherKey[i] == '\0';
	}
					// cout << "cipherKey[16] " << cipherKey[16] << endl;




	if ((cipherType == "DES" || cipherType == "des") && cipherKeyLength == DES_KEY_LENGTH) {
		/* Create an instance of the DES cipher */
		cipher = new DES();
		blockSize = 8;
	}
	else if ((cipherType == "AES" || cipherType == "aes") && cipherKeyLength == AES_KEY_LENGTH)  {
		cipher = new AES();
		blockSize = 16;
	}
	else {
		fprintf(stderr, "ERROR [%s %s %d]: Invalid encryption type. Please use DES or AES \n",
		__FILE__, __FUNCTION__, __LINE__);
		exit(-1);
	}

	/* Error checks */
	if(!cipher)
	{
		fprintf(stderr, "ERROR [%s %s %d]: could not allocate memory\n",
		__FILE__, __FUNCTION__, __LINE__);
		exit(-1);
	}

	// cipher->setKey((unsigned char*)cipherKey);
	// string s( reinterpret_cast< char const* >(honestCipher) ) ;
	// cout <<"s = " << s.erase(0,1) <<endl;
	// cout <<"honset = " << honestCipher <<endl;
	// unsigned char *temp =(unsigned char *)s.c_str();
	if (cipher->setKey(honestCipher)) {
		// fprintf(stderr, "ERROR [%s %s %d]:  Invalid cipher key!\n",
		// __FILE__, __FUNCTION__, __LINE__);
		// exit(-1);
	}


	// Open file
	ifstream inputFileStream;
	inputFileStream.open(inputFileName, ios::in);
	ofstream outputFileStream;
	outputFileStream.open(outputFileName, ios::out);


	unsigned char * blockCiphertext = new unsigned char [blockSize];
	stringstream sstr;
	unsigned char c;



	while (inputFileStream >> noskipws >> c) {
		unsigned char * blockPlaintext = new unsigned char [9] ;
		fill(blockPlaintext, blockPlaintext + 9, ' ');
		blockPlaintext[0] = c;
		cout << noskipws << c << " ";
		blockPlaintext[8] = '\0';

		for (int i = 1; i < 8; ++i) {
			if (inputFileStream >> noskipws >> c) {
				cout << noskipws << c << " ";
				blockPlaintext[i] = c;
			}
			else {
				cout << "<break>" << " ";
				//break;
			}
		}

		if (encodingType == "ENC") {
			outputFileStream << cipher->encrypt(blockPlaintext);
		}
		else if (encodingType == "DEC") {
			outputFileStream << cipher->decrypt(blockPlaintext);
		}
		else {
			fprintf(stderr, "ERROR [%s %s %d]: Invalid encryption type. Please use DES or AES \n",
		__FILE__, __FUNCTION__, __LINE__);
		exit(-1);
		}

		delete [] blockPlaintext;
	}


	/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
		cout << "\nOutput for Step " << mainTraceIterator << endl;
		++mainTraceIterator;

		cout << "cipherType" << ": " << cipherType << endl;
		cout << "cipherKeyString" << ": " << cipherKeyString << endl;
		cout << "cipherKeyStringSpiteCpp" << ": " << cipherKeyStringSpiteCpp << endl;
		cout << "encodingType" << ": " << encodingType << endl;
		cout << "inputFileName" << ": " << inputFileName << endl;
		cout << "outputFileName" << ": " << outputFileName << endl;
		cout << "cipherKeyLength" << ": " << cipherKeyLength << endl;
		cout << "cipherKey" << ": " << cipherKey << endl;
		cout << "blockSize" << ": " << blockSize << endl;

		// cout << "strlen(cipherKey)" << ": " << strlen(cipherKey) << endl;




	/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/


	inputFileStream.close();
	outputFileStream.close();


	delete [] blockCiphertext;

	return 0;
}
