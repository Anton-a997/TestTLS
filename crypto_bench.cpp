#include "crypto_bench.h"

#include <stdio.h>
#include <string.h>

#include <chrono>

using namespace std::chrono;

int b_add_cert_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;

    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);

    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);

    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);

    return 1;
}

bool b_create_ca_cert(int alg)
{
    EVP_PKEY* pkey;

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
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
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

    if (!b_add_cert_ext(x509, NID_basic_constraints, (char*)"CA:TRUE")
            || !b_add_cert_ext(x509, NID_key_usage, (char*)"keyCertSign,cRLSign")
            || !b_add_cert_ext(x509, NID_subject_key_identifier, (char*)"hash")
            || !b_add_cert_ext(x509, NID_authority_key_identifier, (char*)"keyid:always"))
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
        return false;
    }

    if (!err)
    {
        fprintf(stderr, "X509_sign failed\n");
        EVP_PKEY_free(pkey);
        X509_free(x509);

        return false;
    }

    system("mkdir cert");

    FILE * f;
    fopen_s(&f, "cert\\test-ca-key.pem", "wb");

    PEM_write_PrivateKey(
        f,                  /* write the key to the file we've opened */
        pkey,               /* our key from earlier */
        NULL,               /* default cipher for encrypting the key on disk */
        NULL,               /* passphrase required for decrypting the key on disk */
        10,                 /* length of the passphrase string */
        NULL,               /* callback for requesting a password */
        NULL                /* data to pass to the callback */
    );

    fclose(f);
    fopen_s(&f, "cert\\test-ca-cert.pem", "wb");

    PEM_write_X509(
        f,   /* write the certificate to the file we've opened */
        x509 /* our certificate */
    );

    fclose(f);

    EVP_PKEY_free(pkey);
    X509_free(x509);

    return true;
}

X509_REQ* b_create_server_req(int alg)
{
    EVP_PKEY* pkey;

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
    X509_REQ_set_version(x509req, 2);

    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"UA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"TLS 1.3 Server", -1, -1, 0);

    if (!X509_REQ_set_subject_name(x509req, name))
    {
        fprintf(stderr, "X509_REQ_set_subject_name failed\n");
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
        return NULL;
    }

    if (!err)
    {
        fprintf(stderr, "X509_REQ_sign failed\n");
        EVP_PKEY_free(pkey);
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
        return false;
    }

    if (NULL == (p_ca_key_pkey = PEM_read_PrivateKey(p_ca_key_file, NULL, NULL, NULL)))
    {
        return false;
    }

    if (NULL == (p_generated_cert = X509_new()))
    {
        return false;
    }

    X509_set_version(p_generated_cert, 2);

    p_serial_number = ASN1_INTEGER_new();
    b_randSerial(p_serial_number);
    X509_set_serialNumber(p_generated_cert, p_serial_number);

    X509_set_issuer_name(p_generated_cert, X509_REQ_get_subject_name(x509req));
    X509_set_subject_name(p_generated_cert, X509_REQ_get_subject_name(x509req));

    X509_gmtime_adj(X509_get_notBefore(p_generated_cert), 0L);
    X509_gmtime_adj(X509_get_notAfter(p_generated_cert), 31536000L);

    if (!b_add_cert_ext(p_generated_cert, NID_key_usage, (char*)"digitalSignature")
            || !b_add_cert_ext(p_generated_cert, NID_subject_key_identifier, (char*)"hash"))
    {
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        return false;
    }

    if (NULL == (p_cert_req_pkey = X509_REQ_get_pubkey(x509req)))
    {
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        return false;
    }

    if (0 > X509_set_pubkey(p_generated_cert, p_cert_req_pkey))
    {
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        return false;
    }

    if (0 > EVP_PKEY_copy_parameters(p_ca_pkey, p_ca_key_pkey))
    {
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        return false;
    }

    X509_set_issuer_name(p_generated_cert, X509_get_subject_name(p_ca_cert));

    int err = 0;
    steady_clock::time_point start, stop;

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
        return false;
    }

    if (0 > err)
    {
        X509_free(p_generated_cert);
        p_generated_cert = NULL;
        return false;
    }

    auto duration = duration_cast<microseconds>(stop - start);
    time_sign = duration.count();

    start = high_resolution_clock::now();
    int verif = X509_verify(p_generated_cert, p_ca_pkey);
    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    time_verify = duration.count();

    if (verif == -1)
        time_verify = 0;

    X509_free(p_ca_cert);
    EVP_PKEY_free(p_ca_pkey);
    EVP_PKEY_free(p_ca_key_pkey);
    ASN1_INTEGER_free(p_serial_number);
    EVP_PKEY_free(p_cert_req_pkey);

    return true;
}
