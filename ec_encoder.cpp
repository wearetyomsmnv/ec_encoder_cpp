#include <iostream>
#include <vector>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    EVP_PKEY_CTX *ctx;
    size_t secret_len;
    unsigned char *secret;

    // Create the context for the shared secret derivation
    ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) return {};

    // Initialize the shared secret derivation
    if (EVP_PKEY_derive_init(ctx) <= 0) return {};

    // Provide the peer public key
    if (EVP_PKEY_derive_set_peer(ctx, peer_public_key) <= 0) return {};

    // Determine buffer length for shared secret
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) return {};

    // Create buffer for shared secret
    secret = (unsigned char *)OPENSSL_malloc(secret_len);

    // Derive the shared secret
    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) return {};

    // Use the derived secret for encryption (AES-128-CBC for this example)
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));
    unsigned char encrypted[1024];
    int encrypted_len = 0;

    EVP_EncryptInit_ex(cipher_ctx, EVP_aes_128_cbc(), NULL, secret, iv);
    EVP_EncryptUpdate(cipher_ctx, encrypted, &encrypted_len, plaintext.data(), plaintext.size());

    int temp_len = 0;
    EVP_EncryptFinal_ex(cipher_ctx, encrypted + encrypted_len, &temp_len);
    encrypted_len += temp_len;

    // Cleanup
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(secret);
    EVP_CIPHER_CTX_free(cipher_ctx);

    return std::vector<unsigned char>(encrypted, encrypted + encrypted_len);
}

std::vector<unsigned char> loadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Не удалось открыть файл: " << filename << std::endl;
        exit(1);
    }
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return data;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Использование: " << argv[0] << " <путь к файлу с шелл-кодом> <путь к файлу с публичным ключом>" << std::endl;
        return 1;
    }

    // Загрузка шелл-кода из файла
    std::vector<unsigned char> shellcode = loadFile(argv[1]);
    
    // Генерация ключей
    EVP_PKEY *my_key = EVP_PKEY_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    
    // Установка кривой
    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, NID_secp256k1, NULL);
    EVP_PKEY_paramgen(pctx, &my_key);

    // Загрузка публичного ключа из файла
    FILE *pubkey_file = fopen(argv[2], "r");
    BIO *pubkey_bio = BIO_new_fp(pubkey_file, BIO_NOCLOSE);
    EVP_PKEY *peer_key = PEM_read_bio_PUBKEY(pubkey_bio, NULL, NULL, NULL);
    BIO_free(pubkey_bio);
    fclose(pubkey_file);

    // Шифрование
    std::vector<unsigned char> encrypted_shellcode = encrypt(shellcode, my_key, peer_key);

    // Запись шифрованного шелл-кода в файл
    std::ofstream outfile("encrypted_shellcode.bin", std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(encrypted_shellcode.data()), encrypted_shellcode.size());
    outfile.close();

    // Освобождение ресурсов
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(peer_key);
}