//g++ -o encrypter encrypter.cpp -ldl
#include <iostream>
#include <iomanip>
#include <sstream>
#include <dlfcn.h>

typedef std::string (*EncryptFunc)(const std::string&, const std::string&);
typedef std::string (*DecryptFunc)(const std::string&, const std::string&);

// Function to convert hex string to bytes
std::string hexToBytes(const std::string& hex) {
    std::string bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte = hex.substr(i, 2);
        char ch = (char) strtol(byte.c_str(), nullptr, 16);
        bytes.push_back(ch);
    }
    return bytes;
}

// Function to convert bytes to hex string
std::string bytesToHex(const std::string& bytes) {
    std::stringstream ss;
    for (unsigned char c : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return ss.str();
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <encrypt/decrypt> <password> <text>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string password = argv[2];
    std::string text = argv[3];

    // Convert hex input to byte string if decrypting
    if (mode == "decrypt") {
        text = hexToBytes(text);
    }

    void* handle = dlopen("./crypto.so", RTLD_LAZY);
    if (!handle) {
        std::cerr << "Error loading library: " << dlerror() << std::endl;
        return 1;
    }

    EncryptFunc encryptAES = (EncryptFunc) dlsym(handle, "encryptAES");
    DecryptFunc decryptAES = (DecryptFunc) dlsym(handle, "decryptAES");
    char* error;
    if ((error = dlerror()) != nullptr) {
        std::cerr << "Error locating function: " << error << std::endl;
        dlclose(handle);
        return 1;
    }

    if (mode == "encrypt") {
        std::string encryptedText = encryptAES(text, password);
        std::cout << "Encrypted text (HEX): " << bytesToHex(encryptedText) << std::endl;
    } else if (mode == "decrypt") {
        std::string decryptedText = decryptAES(text, password);
        std::cout << "Decrypted text: " << decryptedText << std::endl;
    } else {
        std::cerr << "Unknown mode. Use 'encrypt' or 'decrypt'." << std::endl;
    }

    dlclose(handle);
    return 0;
}
