#include "crypto_bench.h"

#include <stdio.h>
#include <string.h>

#include <chrono>

using namespace std::chrono;

int b_add_cert_ext(X509 *cert, int nid, const char *value, X509 *issuer = NULL)
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

bool b_create_ca_cert(int alg)
{
    EVP_PKEY* pkey = NULL;

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

    X509* x509 = X509_new();
    if (!x509)
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L);
    X509_set_version(x509, 2);

    if (!X509_set_pubkey(x509, pkey))
    {
        fprintf(stderr, "X509_set_pubkey failed\n");
        EVP_PKEY_free(pkey);
        X509_free(x509);

        return false;
    }

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"UA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"CA", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (!b_add_cert_ext(x509, NID_basic_constraints, "CA:TRUE")
            || !b_add_cert_ext(x509, NID_key_usage, "keyCertSign,cRLSign")
            || !b_add_cert_ext(x509, NID_subject_key_identifier, "hash")
            || !b_add_cert_ext(x509, NID_authority_key_identifier, "keyid:always"))
    {
        fprintf(stderr, "add_cert_ext failed\n");
        EVP_PKEY_free(pkey);
        X509_free(x509);

        return false;
    }

    int err = 0;

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

    system("mkdir cert");

    FILE * f = NULL;
    if (fopen_s(&f, "cert\\test-ca-key.pem", "wb") != 0 || !f)
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

    if (fopen_s(&f, "cert\\test-ca-cert.pem", "wb") != 0 || !f)
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

X509_REQ* b_create_server_req(int alg)
{
    EVP_PKEY* pkey = NULL;

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

    X509_REQ* x509req = X509_REQ_new();
    if (!x509req)
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    X509_REQ_set_version(x509req, 2);

    X509_NAME* name = X509_NAME_new();
    if (!name)
    {
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);
        return NULL;
    }
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"UA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"TLS 1.3 Server", -1, -1, 0);

    if (!X509_REQ_set_subject_name(x509req, name))
    {
        fprintf(stderr, "X509_REQ_set_subject_name failed\n");
        X509_NAME_free(name);
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);

        return NULL;
    }

    X509_NAME_free(name);

    if (!X509_REQ_set_pubkey(x509req, pkey))
    {
        fprintf(stderr, "X509_REQ_set_pubkey failed\n");
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509req);

        return NULL;
    }

    int err = 0;

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

    EVP_PKEY_free(pkey);

    if (err <= 0)
    {
        fprintf(stderr, "X509_REQ_sign failed\n");
        X509_REQ_free(x509req);

        return NULL;
    }

    return x509req;
}

int b_randSerial(ASN1_INTEGER *ai)
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

bool b_create_server_cert(X509_REQ* x509req, int alg, FILE *p_ca_cert_file, FILE *p_ca_key_file, long long &time_sign, long long &time_verify)
{
    X509 *p_ca_cert = NULL;
    EVP_PKEY *p_ca_pkey = NULL;
    EVP_PKEY *p_ca_key_pkey = NULL;
    X509 *p_generated_cert = NULL;
    ASN1_INTEGER *p_serial_number = NULL;
    EVP_PKEY *p_cert_req_pkey = NULL;

    if (NULL == (p_ca_cert = PEM_read_X509(p_ca_cert_file, NULL, 0, NULL)))
    {
        return false;
    }

    if (NULL == (p_ca_pkey = X509_get_pubkey(p_ca_cert)))
    {
        X509_free(p_ca_cert);
        return false;
    }

    if (NULL == (p_ca_key_pkey = PEM_read_PrivateKey(p_ca_key_file, NULL, NULL, NULL)))
    {
        EVP_PKEY_free(p_ca_pkey);
        X509_free(p_ca_cert);
        return false;
    }

    if (NULL == (p_generated_cert = X509_new()))
    {
        EVP_PKEY_free(p_ca_key_pkey);
        EVP_PKEY_free(p_ca_pkey);
        X509_free(p_ca_cert);
        return false;
    }

    X509_set_version(p_generated_cert, 2);

    p_serial_number = ASN1_INTEGER_new();
    if (!p_serial_number || b_randSerial(p_serial_number) < 0 || !X509_set_serialNumber(p_generated_cert, p_serial_number))
    {
        ASN1_INTEGER_free(p_serial_number);
        X509_free(p_generated_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        EVP_PKEY_free(p_ca_pkey);
        X509_free(p_ca_cert);
        return false;
    }
    ASN1_INTEGER_free(p_serial_number);
    p_serial_number = NULL;

    X509_set_issuer_name(p_generated_cert, X509_get_subject_name(p_ca_cert));
    X509_set_subject_name(p_generated_cert, X509_REQ_get_subject_name(x509req));

    X509_gmtime_adj(X509_getm_notBefore(p_generated_cert), 0L);
    X509_gmtime_adj(X509_getm_notAfter(p_generated_cert), 31536000L);

    p_cert_req_pkey = X509_REQ_get_pubkey(x509req);
    if (!p_cert_req_pkey || !X509_set_pubkey(p_generated_cert, p_cert_req_pkey))
    {
        EVP_PKEY_free(p_cert_req_pkey);
        X509_free(p_generated_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        EVP_PKEY_free(p_ca_pkey);
        X509_free(p_ca_cert);
        return false;
    }
    EVP_PKEY_free(p_cert_req_pkey);
    p_cert_req_pkey = NULL;

    if (!b_add_cert_ext(p_generated_cert, NID_key_usage, "digitalSignature", p_ca_cert)
            || !b_add_cert_ext(p_generated_cert, NID_subject_key_identifier, "hash", p_ca_cert))
    {
        X509_free(p_generated_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        EVP_PKEY_free(p_ca_pkey);
        X509_free(p_ca_cert);
        return false;
    }

    int err = 0;
    high_resolution_clock::time_point start, stop;

    switch (alg)
    {
    case CERT_RSA:
    case CERT_ECDSA:
        start = high_resolution_clock::now();
        err = X509_sign(p_generated_cert, p_ca_key_pkey, EVP_sha256());
        stop = high_resolution_clock::now();
        break;

    case CERT_ED25519:
        start = high_resolution_clock::now();
        err = X509_sign(p_generated_cert, p_ca_key_pkey, NULL);
        stop = high_resolution_clock::now();
        break;

    default:
        X509_free(p_generated_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        EVP_PKEY_free(p_ca_pkey);
        X509_free(p_ca_cert);
        return false;
    }

    if (err <= 0)
    {
        X509_free(p_generated_cert);
        EVP_PKEY_free(p_ca_key_pkey);
        EVP_PKEY_free(p_ca_pkey);
        X509_free(p_ca_cert);
        return false;
    }

    auto duration = duration_cast<microseconds>(stop - start);
    time_sign = duration.count();

    start = high_resolution_clock::now();
    int verif = X509_verify(p_generated_cert, p_ca_pkey);
    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    time_verify = duration.count();

    if (verif <= 0)
        time_verify = 0;

    X509_free(p_generated_cert);
    X509_free(p_ca_cert);
    EVP_PKEY_free(p_ca_pkey);
    EVP_PKEY_free(p_ca_key_pkey);

    return true;
}
