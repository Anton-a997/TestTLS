#include "crypto.h"

#include <stdio.h>
#include <string.h>

void init_openssl()
{
    OPENSSL_init_ssl(0, NULL);
}

void cleanup_openssl()
{
}

SSL_CTX *create_server_context(const char *alg_string)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method(); // TLS сервер
    ctx = SSL_CTX_new(method); // контекст SSL

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION); // TLS 1.3
    SSL_CTX_set1_sigalgs_list(ctx, "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:ed25519"); // алгоритмы подписи
    SSL_CTX_set_ciphersuites(ctx, alg_string); // алгоритм шифрования сессии

    return ctx;
}

SSL_CTX *create_client_context(bool use_keylog)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method(); // TLS клиент
    ctx = SSL_CTX_new(method); // контекст SSL

    remove("cert\\keylog.log"); // файл с данными хендшейка для Wireshark

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION); // TLS 1.3
    SSL_CTX_set1_sigalgs_list(ctx, "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:ed25519"); // алгоритмы подписи

    if (use_keylog)
        SSL_CTX_set_keylog_callback(ctx, keylog_callback); // callback для записи хендшейка в keylog

    return ctx;
}

const char *EVP_PKEY_get_type_name(EVP_PKEY *pubkey)
{
    return EVP_PKEY_get0_type_name(pubkey);
}

void keylog_callback(const SSL*, const char *line)
{
    FILE* of;

    if (fopen_s(&of, "cert\\keylog.log", "a") != 0)
        return;

    fprintf_s(of, "%s\n", line);
    fclose(of);
}

bool load_server_cert(SSL_CTX *ctx, const char* cert_path, const char* key_path)
{
    // загрузка серт сервера
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // загрузка ключа сервера
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}

// добавление расширений сертификата (назначение, использование...)
int add_cert_ext(X509 *cert, int nid, const char *value, X509 *issuer = NULL)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;

    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);

    /* Issuer and subject certs: both the target if self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, issuer ? issuer : cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);

    if (!ex)
        return 0;

    int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);

    return ok;
}

bool create_ca_cert(int alg, const char *fname_cert, const char *fname_key)
{
    EVP_PKEY* pkey = NULL;

    // выбор алгоритма серт и генерация ключа
    switch (alg)
    {
    case CERT_RSA:
        pkey = EVP_RSA_gen(3072);
        break;

    case CERT_ECDSA:
        pkey = EVP_EC_gen("prime256v1");
        break;

    case CERT_ED25519:
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
        break;

    default:
        return false;
    }

    if (!pkey)
    {
        fprintf(stderr, "EVP_PKEY_Q_keygen failed\n");
        return false;
    }

    X509* x509 = X509_new(); // создание серт
    if (!x509)
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); // серийный номер
    X509_gmtime_adj(X509_getm_notBefore(x509), 0); // действует с
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L); // действует по
    X509_set_version(x509, 2); // версия V3

    // задаем открытый ключ
    if (!X509_set_pubkey(x509, pkey))
    {
        fprintf(stderr, "X509_set_pubkey failed\n");
        EVP_PKEY_free(pkey);
        X509_free(x509);

        return false;
    }

    // имя, организация...
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"UA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"CA", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // расширения сертификата
    if (!add_cert_ext(x509, NID_basic_constraints, "CA:TRUE")
            || !add_cert_ext(x509, NID_key_usage, "keyCertSign,cRLSign")
            || !add_cert_ext(x509, NID_subject_key_identifier, "hash")
            || !add_cert_ext(x509, NID_authority_key_identifier, "keyid:always"))
    {
        fprintf(stderr, "add_cert_ext failed\n");
        EVP_PKEY_free(pkey);
        X509_free(x509);

        return false;
    }

    int err = 0;

    // алгоритм хеширования подписи
    switch (alg)
    {
    case CERT_RSA:
    case CERT_ECDSA:
        err = X509_sign(x509, pkey, EVP_sha256());
        break;

    case CERT_ED25519:
        err = X509_sign(x509, pkey, NULL);
        break;

    default:
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return false;
    }

    if (err <= 0)
    {
        fprintf(stderr, "X509_sign failed\n");
        EVP_PKEY_free(pkey);
        X509_free(x509);

        return false;
    }

    // сохранение в файл
    FILE * f = NULL;
    if (fopen_s(&f, fname_key, "wb") != 0 || !f)
    {
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return false;
    }

    int write_key_ok = PEM_write_PrivateKey(
        f,                  /* write the key to the file we've opened */
        pkey,               /* our key from earlier */
        NULL,               /* default cipher for encrypting the key on disk */
        NULL,               /* passphrase required for decrypting the key on disk */
        0,                  /* length of the passphrase string */
        NULL,               /* callback for requesting a password */
        NULL                /* data to pass to the callback */
    );
    fclose(f);

    if (!write_key_ok)
    {
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return false;
    }

    if (fopen_s(&f, fname_cert, "wb") != 0 || !f)
    {
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return false;
    }

    int write_cert_ok = PEM_write_X509(
        f,   /* write the certificate to the file we've opened */
        x509 /* our certificate */
    );
    fclose(f);

    EVP_PKEY_free(pkey);
    X509_free(x509);

    return write_cert_ok != 0;
}

X509_REQ* create_server_req(int alg, const char *fname_req, const char *fname_key)
{
    EVP_PKEY* pkey = NULL;

    // генерация ключа
    switch (alg)
    {
    case CERT_RSA:
        pkey = EVP_RSA_gen(3072);
        break;

    case CERT_ECDSA:
        pkey = EVP_EC_gen("prime256v1");
        break;

    case CERT_ED25519:
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
        break;

    default:
        return NULL;
    }

    if (!pkey)
    {
        fprintf(stderr, "EVP_PKEY_Q_keygen failed\n");
        return NULL;
    }

    // создания серт запроса
    X509_REQ* x509req = X509_REQ_new();
    if (!x509req)
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    X509_REQ_set_version(x509req, 2);

    // имя, страна...
    X509_NAME* name = X509_NAME_new();
    if (!name)
    {
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);
        return NULL;
    }
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"UA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"TLS 1.3 Server", -1, -1, 0);

    // установка имени
    if (!X509_REQ_set_subject_name(x509req, name))
    {
        fprintf(stderr, "X509_REQ_set_subject_name failed\n");
        X509_NAME_free(name);
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);

        return NULL;
    }

    X509_NAME_free(name);

    // установка открытого ключа
    if (!X509_REQ_set_pubkey(x509req, pkey))
    {
        fprintf(stderr, "X509_REQ_set_pubkey failed\n");
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);

        return NULL;
    }

    int err = 0;

    // алгоритм хеширования
    switch (alg)
    {
    case CERT_RSA:
    case CERT_ECDSA:
        err = X509_REQ_sign(x509req, pkey, EVP_sha256());
        break;

    case CERT_ED25519:
        err = X509_REQ_sign(x509req, pkey, NULL);
        break;

    default:
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);
        return NULL;
    }

    if (err <= 0)
    {
        fprintf(stderr, "X509_REQ_sign failed\n");
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);

        return NULL;
    }

    // запись в файл
    FILE * f = NULL;
    if (fopen_s(&f, fname_key, "wb") != 0 || !f)
    {
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);
        return NULL;
    }

    int write_key_ok = PEM_write_PrivateKey(
        f,                  /* write the key to the file we've opened */
        pkey,               /* our key from earlier */
        NULL,               /* default cipher for encrypting the key on disk */
        NULL,               /* passphrase required for decrypting the key on disk */
        0,                  /* length of the passphrase string */
        NULL,               /* callback for requesting a password */
        NULL                /* data to pass to the callback */
    );
    fclose(f);

    if (!write_key_ok)
    {
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);
        return NULL;
    }

    if (fopen_s(&f, fname_req, "wb") != 0 || !f)
    {
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);
        return NULL;
    }

    int write_req_ok = PEM_write_X509_REQ(
        f,      /* write the certificate to the file we've opened */
        x509req /* our certificate */
    );
    fclose(f);

    EVP_PKEY_free(pkey);

    if (!write_req_ok)
    {
        X509_REQ_free(x509req);
        return NULL;
    }

    return x509req;
}

// генерация серийного номера
int randSerial(ASN1_INTEGER *ai)
{
    BIGNUM *p_bignum = NULL;

    if (NULL == (p_bignum = BN_new()))
    {
        return -1;
    }

    if (!BN_rand(p_bignum, 64, 0, 0))
    {
        BN_free(p_bignum);
        return -1;
    }

    if (ai && !BN_to_ASN1_INTEGER(p_bignum, ai))
    {
        BN_free(p_bignum);
        return -1;
    }

    BN_free(p_bignum);
    return 1;
}

bool create_server_cert(X509_REQ* x509req, int alg, const char* p_ca_cert_path, const char* p_ca_key_path, const char* fname_serv_cert)
{
    FILE *p_ca_cert_file = NULL;
    X509 *p_ca_cert = NULL;
    FILE *p_ca_key_file = NULL;
    EVP_PKEY *p_ca_key_pkey = NULL;
    X509 *p_generated_cert = NULL;
    ASN1_INTEGER *p_serial_number = NULL;
    EVP_PKEY *p_cert_req_pkey = NULL;

    // чтение серт ЦС
    if (fopen_s(&p_ca_cert_file, p_ca_cert_path, "r") != 0 || !p_ca_cert_file)
    {
        return false;
    }

    p_ca_cert = PEM_read_X509(p_ca_cert_file, NULL, 0, NULL);
    fclose(p_ca_cert_file);
    if (!p_ca_cert)
    {
        return false;
    }

    if (fopen_s(&p_ca_key_file, p_ca_key_path, "r") != 0 || !p_ca_key_file)
    {
        X509_free(p_ca_cert);
        return false;
    }

    // чтение закрытого ключа ЦС
    p_ca_key_pkey = PEM_read_PrivateKey(p_ca_key_file, NULL, NULL, NULL);
    fclose(p_ca_key_file);
    if (!p_ca_key_pkey)
    {
        X509_free(p_ca_cert);
        return false;
    }

    // новый серт
    p_generated_cert = X509_new();
    if (!p_generated_cert)
    {
        X509_free(p_ca_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        return false;
    }

    X509_set_version(p_generated_cert, 2); // версия V3

    p_serial_number = ASN1_INTEGER_new(); // серийный номер
    if (!p_serial_number || randSerial(p_serial_number) < 0 || !X509_set_serialNumber(p_generated_cert, p_serial_number))
    {
        ASN1_INTEGER_free(p_serial_number);
        X509_free(p_generated_cert);
        X509_free(p_ca_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        return false;
    }
    ASN1_INTEGER_free(p_serial_number);
    p_serial_number = NULL;

    X509_set_issuer_name(p_generated_cert, X509_get_subject_name(p_ca_cert)); // выдан кем
    X509_set_subject_name(p_generated_cert, X509_REQ_get_subject_name(x509req)); // выдан кому

    X509_gmtime_adj(X509_getm_notBefore(p_generated_cert), 0L); // действует от
    X509_gmtime_adj(X509_getm_notAfter(p_generated_cert), 31536000L); // действует до

    // установка открытого ключа серт сервера из сертификата REQ
    p_cert_req_pkey = X509_REQ_get_pubkey(x509req);
    if (!p_cert_req_pkey || !X509_set_pubkey(p_generated_cert, p_cert_req_pkey))
    {
        EVP_PKEY_free(p_cert_req_pkey);
        X509_free(p_generated_cert);
        X509_free(p_ca_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        return false;
    }
    EVP_PKEY_free(p_cert_req_pkey);
    p_cert_req_pkey = NULL;

    // расширения
    if (!add_cert_ext(p_generated_cert, NID_key_usage, "digitalSignature", p_ca_cert)
            || !add_cert_ext(p_generated_cert, NID_subject_key_identifier, "hash", p_ca_cert))
    {
        X509_free(p_generated_cert);
        X509_free(p_ca_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        return false;
    }

    int err = 0;

    // подписание серт сервера
    switch (alg)
    {
    case CERT_RSA:
    case CERT_ECDSA:
        err = X509_sign(p_generated_cert, p_ca_key_pkey, EVP_sha256());
        break;

    case CERT_ED25519:
        err = X509_sign(p_generated_cert, p_ca_key_pkey, NULL);
        break;

    default:
        X509_free(p_generated_cert);
        X509_free(p_ca_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        return false;
    }

    if (err <= 0)
    {
        X509_free(p_generated_cert);
        X509_free(p_ca_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        return false;
    }

    // запись в файл
    FILE * f = NULL;
    if (fopen_s(&f, fname_serv_cert, "wb") != 0 || !f)
    {
        X509_free(p_generated_cert);
        X509_free(p_ca_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        return false;
    }

    int write_ok = PEM_write_X509(
        f,
        p_generated_cert
    );
    fclose(f);

    X509_free(p_generated_cert);
    X509_free(p_ca_cert);
    EVP_PKEY_free(p_ca_key_pkey);

    return write_ok != 0;
}

int tls_recv_packet(SSL* ssl, char* buf, int max_size)
{
    int len = 0;
    char* rd_buf = buf;

    do
    {
        len = SSL_read(ssl, rd_buf, max_size - (int)(rd_buf - buf));
        rd_buf += len;
    } while (len > 0);

    if (len < 0)
    {
        int err = SSL_get_error(ssl, len);

        if (err == SSL_ERROR_WANT_READ)
            return (int)(rd_buf - buf);
        if (err == SSL_ERROR_WANT_WRITE)
            return (int)(rd_buf - buf);
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -err;
    }

    return (int)(rd_buf - buf);
}

int tls_send_packet(SSL* ssl, const char *buf, int size)
{
    int len = SSL_write(ssl, buf, size);

    if (len < 0)
    {
        int err = SSL_get_error(ssl, len);

        if (err == SSL_ERROR_WANT_READ)
            return 0;
        if (err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -err;
    }

    return len;
}
