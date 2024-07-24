#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <fstream>

typedef std::vector<unsigned char> Buffer;

namespace Crypto {
    int EncryptAES(const Buffer& plaintext, const Buffer& key, Buffer &ciphertext) {
        Buffer iv(AES_BLOCK_SIZE);
        if (RAND_bytes(iv.data(), AES_BLOCK_SIZE) != 1) {
            std::cerr << "Error generating random IV." << std::endl;
            return 1;
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
            std::cerr << "Error creating EVP_CIPHER_CTX." << std::endl;
            return 2;
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            std::cerr << "Error initializing AES encryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return 3;
        }

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);

        int len = 0;
        int ciphertext_len = 0;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            std::cerr << "Error encrypting data." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return 4;
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len) != 1) {
            std::cerr << "Error finalizing AES encryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return 5;
        }
        ciphertext_len += len;

        ciphertext.resize(ciphertext_len);

        ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());

        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int DecryptAES(const Buffer& ciphertext, const Buffer& key, Buffer &plaintext) {

        Buffer iv(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
            std::cerr << "Error creating EVP_CIPHER_CTX." << std::endl;
            return 1;
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            std::cerr << "Error initializing AES decryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return 2;
        }

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        plaintext.resize(ciphertext.size() - AES_BLOCK_SIZE);

        int len = 0;
        int plaintext_len = 0;

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data() + AES_BLOCK_SIZE, ciphertext.size() - AES_BLOCK_SIZE) != 1) {
            std::cerr << "Error decrypting data." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return 3;
        }
        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len) != 1) {
            std::cerr << "Error finalizing AES decryption." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return 4;
        }
        plaintext_len += len;

        plaintext.resize(plaintext_len);

        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int GenerateRandomKey(Buffer &key) {
        key.resize(32);

        if (RAND_bytes(key.data(), key.size()) != 1) {
            return 1;
        }

        return 0;
    }
};

int DumpVector(const Buffer &v, std::ofstream &file) {
    for (const auto &byte : v) {
        file << byte;
    }

    return v.size();
}

int LoadVector(Buffer &v, std::ifstream &file) {
    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    v.resize(fileSize);
    file.read(reinterpret_cast<char *>(v.data()), fileSize);
    return v.size();
}

namespace User {
    void GenerateRandomKey(const std::string &filename) {
        Buffer key;
        std::ofstream file(filename);

        if (Crypto::GenerateRandomKey(key) != 0) {
            std::cerr << "Error generating random key." << std::endl;
            return;
        }

        DumpVector(key, file);
        file.close();
    }

    void EncryptFile(const std::string &key_filename, const std::string &data_filename, const std::string &output_filename) {
        std::ifstream key_file(key_filename);
        std::ifstream data_file(data_filename);
        std::ofstream output_file(output_filename);

        Buffer key, data, output;

        LoadVector(key, key_file);
        LoadVector(data, data_file);
        std::cout << "key has " << key.size() << " bytes" << std::endl;
        std::cout << "data has " << data.size() << " bytes" << std::endl;

        if (Crypto::EncryptAES(data, key, output) != 0) {
            std::cerr << "Couldn't encrypt file!" << std::endl;
            return;
        }

        DumpVector(output, output_file);
        output_file.close();
        std::cout << "Written " << output.size() << " bytes of encrypted data." << std::endl;
    }

    void DecryptFile(const std::string &key_filename, const std::string &data_filename, const std::string &output_filename) {
        std::ifstream key_file(key_filename);
        std::ifstream encrypted_data_file(data_filename);
        std::ofstream output_file(output_filename);

        Buffer key, encrypted_data, output;

        LoadVector(key, key_file);
        LoadVector(encrypted_data, encrypted_data_file);
        std::cout << "key has " << key.size() << " bytes" << std::endl;
        std::cout << "encrypted data has " << encrypted_data.size() << " bytes" << std::endl;

        if (Crypto::DecryptAES(encrypted_data, key, output) != 0) {
            std::cerr << "Couldn't decrypt file!" << std::endl;
            return;
        }
        DumpVector(output, output_file);
        output_file.close();
        std::cout << "Written " << output.size() << " bytes of decrypted data." << std::endl;
    }
};

int main(int argc, char *argv[]) {

    if (argc < 2) {
        std::cerr << "Insufficient arguments provided!" << std::endl;
        std::cerr << "See `" << argv[0] << " h` for help" << std::endl;
        return 1;
    }

    if (argv[1][0] == 'h') {
        std::cout << "This is firolock. The software that keeps your data 100\% safe and encrypted," << std::endl\
                  << "where you are the one and only with access to your keys and data." << std::endl << std::endl;
        std::cout << "Usage" << std::endl\
                  << "-----" << std::endl\
                  << "  - Generation:" << std::endl\
                  << "      " << argv[0] << " g <output file>" << std::endl\
                  << "      Generates a random and safe key saved in <output file>" << std::endl << std::endl\
                  << "      Example: " << argv[0] << " g master.key" << std::endl\
                  << "               This command generates a random and secure key and saves it in `master.key` file" << std::endl << std::endl\

                  << "  - Encryption:" << std::endl\
                  << "      " << argv[0] << " e <key file> <input file> <output file>" << std::endl\
                  << "      Encrypts <input file> with key from <key file> and saves in <output file>" << std::endl << std::endl\
                  << "      Example: " << argv[0] << " e master.key data.txt" << std::endl\
                  << "               This command encrypts the contents of the `data.txt` file using the key stored in" <<std::endl\
                  << "               `master.key` and saves the encrypted data in `encrypted.bin`." << std::endl << std::endl\

                  << "  - Decryption:" << std::endl\
                  << "      " << argv[0] << " d <key file> <input file> <output file>" << std::endl\
                  << "      Decrypts <input file> with key from <key file> and saves in <output file>" << std::endl << std::endl\
                  << "      Example: " << argv[0] << " d master.key encrypted.bin data.dec" << std::endl\
                  << "               This command decrypts the contents of the `encrypted.bin` file using the key stored in" <<std::endl\
                  << "               `master.key` and saves the encrypted data in `data.dec`." << std::endl << std::endl\

                  << "Note: The <key file> should be a text/binary file containing the encryption key." << std::endl\
                  << "      The <input file> and <output file> can be any file type." << std::endl;

        return 0;
    }

    if ((argc < 3 and argv[1][0] == 'g') or (argc < 4 and argv[1][0] != 'g')) {
        std::cerr << "Insufficient arguments provided!" << std::endl;
        return 1;
    }

    switch (argv[1][0]) {
    case 'g':
        User::GenerateRandomKey(argv[2]);
        break;
    case 'e':
        User::EncryptFile(argv[2], argv[3], argv[4]);
        break;
    case 'd':
        User::DecryptFile(argv[2], argv[3], argv[4]);
        break;
    default:
        std::cerr << "Invalid instruction (" << argv[1] << ")\n";
        break;
    }

    return 0;
}
