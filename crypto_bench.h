#ifndef CRYPTO_BENCH_H
#define CRYPTO_BENCH_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ec.h>

#define CERT_RSA 1
#define CERT_ECDSA 2
#define CERT_ED25519 3

bool b_create_ca_cert(int alg);
X509_REQ* b_create_server_req(int alg);
bool b_create_server_cert(X509_REQ* x509req, int alg, FILE *p_ca_cert_file, FILE *p_ca_key_file, long long& time_sign, long long& time_verify);

#endif // CRYPTO_BENCH_H
