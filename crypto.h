#ifndef CRYPTO_H
#define CRYPTO_H

#pragma comment( lib, "Ws2_32" )
#pragma comment( lib, "User32" )
#pragma comment( lib, "Crypt32" )
#pragma comment( lib, "Advapi32" )
#pragma comment( lib, "..\\TestTLS\\libssl64MD" )
#pragma comment( lib, "..\\TestTLS\\libcrypto64MD" )

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>

#define CERT_RSA 1
#define CERT_ECDSA 2
#define CERT_ED25519 3

void init_openssl();
void cleanup_openssl();
SSL_CTX *create_server_context(const char* alg_string); // настройка контекста сервера
SSL_CTX *create_client_context(bool use_keylog); // настройка контекста клиента
const char* EVP_PKEY_get_type_name(EVP_PKEY* pubkey);
void keylog_callback(const SSL *ssl, const char *line);
bool load_server_cert(SSL_CTX *ctx, const char *cert_path, const char *key_path); // загрузка сертификатов сервера
bool create_ca_cert(int alg, const char* fname_cert, const char* fname_key); // создание серт ЦС
X509_REQ* create_server_req(int alg, const char* fname_req, const char* fname_key); // создание серт REQ
bool create_server_cert(X509_REQ* x509req, int alg, const char* p_ca_cert_path, const char* p_ca_key_path, const char* fname_serv_cert);  // создание серт сервера
int tls_recv_packet(SSL* ssl, char *buf, int max_size); // чтение пакета TLS
int tls_send_packet(SSL* ssl, const char *buf, int size); // отправка пакета TLS

#endif // CRYPTO_H
