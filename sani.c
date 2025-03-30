// sani.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



int main(void) {
    (void)crypto_iv;
    printf("test\n");
    return 0;
}

/*
Przykładowa implementacja funkcji kryptograficznych:

// Inicjalizacja systemu kryptograficznego.
int crypto_init(const char *iv) {
    printf("crypto_init wywołane z IV: %s\n", iv);
    return 0;
}

// Funkcja szyfrująca XOR
char *crypto_encrypt(const char *secret, const char *plaintext) {
    int key = secret[0];  
    int len = strlen(plaintext);
    char *encrypted = malloc(len + 1);
    if (!encrypted) return NULL;
    
    for (int i = 0; i < len; i++) {
        encrypted[i] = plaintext[i] ^ key;
    }
    encrypted[len] = '\0';  
    return encrypted;
}

// Funkcja deszyfrująca XOR
char *crypto_decrypt(const char *secret, const char *ciphertext) {
    return crypto_encrypt(secret, ciphertext);
}

// Przykladowy wektor inicjalizacyjny IV
static const char *crypto_iv = "iv12345678";
*/


