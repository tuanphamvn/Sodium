#include <stdio.h>
#include <conio.h>
#include <sodium.h>
#include <string.h>

void PrintArray(unsigned char* s, int len)
{
	for (int i = 0; i < len; i++)
	{
		putchar(s[i]);
	}
}

void main()
{
	//INIT SODIUM
	if (sodium_init() == -1) {
		return;
	}
	
	char message[100];
	printf("Please enter your original message:");
	gets(message);

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char key[crypto_secretbox_KEYBYTES];
	randombytes_buf(nonce, sizeof nonce);
	randombytes_buf(key, sizeof key);

	//ENCRYPTION
	printf("\nOriginal Message: %s", message);
	printf("\nEncrytion Key:");
	PrintArray(key, crypto_secretbox_KEYBYTES);

	int messageLength = strlen(message) + 1; //include the '\0' character
	int cipherTextLength = (crypto_secretbox_MACBYTES + messageLength);
	char *cipherText = new char[cipherTextLength];
	crypto_secretbox_easy((unsigned char*)cipherText, (unsigned char*)message, messageLength, nonce, key);

	printf("\nEncrypted Message: ");
	PrintArray((unsigned char*)cipherText, cipherTextLength);

	//DECRYPTION
	char *decrypted = new char[messageLength];
	if (crypto_secretbox_open_easy((unsigned char*)decrypted, (unsigned char*)cipherText, cipherTextLength, nonce, key) == 0) {
		printf("\nDecrypted Message: %s\n", decrypted);
	}
	else {
		printf("\nDescryption failed.\n");
	}

	getch();
}