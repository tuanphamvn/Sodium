#include <stdio.h>
#include <conio.h>
#include <sodium.h>
#include <string.h>

#define GENERATEKEY 0
#define SIGNING 1
#define VERIFYING 2
#define EXITING 3

#define KEY_PAIR_FILE_PATH "d:\key.bin"
#define DIGITAL_DATA_FILE_PATH "d:\digitaldata.bin"

void SaveDigitalData(char *message, int messageLen, unsigned char *signature, unsigned long long signatureLen, char *filePath)
{
	FILE* file = fopen(filePath, "wb");
	if (file == NULL)
	{
		printf("Cannot create the file %s", filePath);
		return;
	}

	fwrite(&messageLen, sizeof(int), 1, file);
	fwrite(&signatureLen, sizeof(unsigned long long), 1, file);
	fwrite(message, sizeof(unsigned char), messageLen, file);
	fwrite(signature, sizeof(unsigned char), signatureLen, file);

	fclose(file);
}

void LoadDigitalData(char *&message, int &messageLen, unsigned char *&signature, unsigned long long &signatureLen, char *filePath)
{
	FILE* file = fopen(filePath, "rb");
	if (file == NULL)
	{
		printf("Cannot open the file %s", filePath);
		return;
	}

	fread(&messageLen, sizeof(int), 1, file);
	fread(&signatureLen, sizeof(unsigned long long), 1, file);
	message = new char[messageLen];
	signature = new unsigned char[signatureLen];
	fread(message, sizeof(unsigned char), messageLen, file);
	fread(signature, sizeof(unsigned char), signatureLen, file);

	fclose(file);
}

void  Signing(char* message, unsigned char *sk, unsigned char* &signature, unsigned long long &signatureLen)
{
	unsigned char hash[crypto_generichash_BYTES];
	crypto_generichash(hash, sizeof hash, (unsigned char*)message, strlen(message), NULL, 0);

	signature = new unsigned char[crypto_sign_BYTES + sizeof hash];

	crypto_sign(signature, &signatureLen, hash, sizeof hash, sk);

}

bool Verifying(char* message, int messageLen, unsigned char* signature, int signatureLen, unsigned char* pk)
{
	unsigned char hash[crypto_generichash_BYTES];
	crypto_generichash(hash, sizeof hash, (unsigned char*)message, messageLen, NULL, 0);

	unsigned char unsealed_message[sizeof hash];
	unsigned long long unsealed_message_len;
	
	if (crypto_sign_open(unsealed_message, &unsealed_message_len, signature, signatureLen, pk) == 0) 
	{
		//Decrypt OK, now compare the 2 hashes
		if (memcmp(hash, unsealed_message, sizeof hash) == 0)
		{
			return 1;
		}
		return 0;
	}

	return 0;
}

void PreparingKeyPair(unsigned char *pk, unsigned char *sk)
{
	FILE* file = fopen(KEY_PAIR_FILE_PATH, "rb");
	if (file == NULL)
	{
		printf("Cannot read the key pair file %s, so we will generate a key pair automatically.\n", KEY_PAIR_FILE_PATH);
		file = fopen(KEY_PAIR_FILE_PATH, "wb");
		if (file == NULL)
		{
			printf("Cannot create the file %s", KEY_PAIR_FILE_PATH);
			return;
		}

		crypto_sign_keypair(pk, sk);
		fwrite(pk, sizeof(unsigned char), crypto_sign_PUBLICKEYBYTES, file);
		fwrite(sk, sizeof(unsigned char), crypto_sign_SECRETKEYBYTES, file);

		fclose(file);
		return;
	}

	fread(pk, sizeof(unsigned char), crypto_sign_PUBLICKEYBYTES, file);
	fread(sk, sizeof(unsigned char), crypto_sign_SECRETKEYBYTES, file);

	fclose(file);
}

int PrintMenu()
{
	printf("------DIGITAL SIGNATURE DEMO------\n");
	printf("1. Sign a message and save to file\n");
	printf("2. Verify a signed message from file\n");
	printf("3. Exit\n");
	printf("Please select an option (1, 2 or 3):");
	int option;
	scanf("%d", &option);
	return option;
}

void main()
{
	//INIT SODIUM
	if (sodium_init() == -1) {
		return;
	}
	
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
	PreparingKeyPair(pk, sk);

	int option;
	unsigned long long signatureLen;
	unsigned char* signature = NULL;

	while ((option = PrintMenu()) != EXITING)
	{
		if (option == SIGNING)
		{
			char message[100];
			printf("Please enter your original message:");
			flushall();
			gets(message);
			
			Signing(message, sk, signature, signatureLen);

			SaveDigitalData(message, strlen(message), signature, signatureLen, DIGITAL_DATA_FILE_PATH);

			delete[] signature;

		}
		else if (option == VERIFYING)
		{
			char *message;
			int messageLen;
			LoadDigitalData(message, messageLen, signature, signatureLen, DIGITAL_DATA_FILE_PATH);

			int iSOK = Verifying(message, messageLen, signature, signatureLen, pk);

			if (iSOK)
			{
				printf("THIS IS A VALID SIGNATURE\n");
			}
			else
			{
				printf("THIS IS NOT A VALID SIGNATURE\n");
			}

			delete[] message;
			delete[] signature;
		}
	}
}