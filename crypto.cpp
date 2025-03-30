//g++ -shared -fPIC -o crypto.so crypto.cpp -lssl -lcrypto
#include <iostream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>

#define AES_KEYLEN 32  // 256-bit key
#define AES_IVLEN 16   // 128-bit IV

// Static IV
const unsigned char IV[AES_IVLEN] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                                     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

// Function to derive key from password
void deriveKey(const std::string& password, unsigned char* key) {
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                   reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), 1, key, nullptr);
}

// AES-256-CBC Encryption
extern "C" std::string encryptAES(const std::string& plaintext, const std::string& password) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error initializing context." << std::endl;
        return "";
    }

    unsigned char key[AES_KEYLEN];
    deriveKey(password, key);
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, IV) != 1) {
        std::cerr << "Error initializing AES." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    int len;
    std::string ciphertext(plaintext.size() + AES_IVLEN, '\0');
    
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                           reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length()) != 1) {
        std::cerr << "Encryption error." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    int ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len) != 1) {
        std::cerr << "Final encryption error." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// AES-256-CBC Decryption
extern "C" std::string decryptAES(const std::string& ciphertext, const std::string& password) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error initializing context." << std::endl;
        return "";
    }

    unsigned char key[AES_KEYLEN];
    deriveKey(password, key);
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, IV) != 1) {
        std::cerr << "Error initializing AES." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    int len;
    std::string plaintext(ciphertext.size(), '\0');
    
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                           reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length()) != 1) {
        std::cerr << "Decryption error." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    int plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len) != 1) {
        std::cerr << "Final decryption error." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}
