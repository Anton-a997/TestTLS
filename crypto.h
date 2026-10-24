#ifndef CRYPTO_H
#define CRYPTO_H

#include <memory>
#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/x509v3.h>

enum class CertAlgorithm
{
    Rsa = 1,
    Ecdsa = 2,
    Ed25519 = 3
};

struct EvpPkeyDeleter { void operator()(EVP_PKEY *p) const noexcept { EVP_PKEY_free(p); } };
struct X509Deleter { void operator()(X509 *p) const noexcept { X509_free(p); } };
struct X509ReqDeleter { void operator()(X509_REQ *p) const noexcept { X509_REQ_free(p); } };
struct X509NameDeleter { void operator()(X509_NAME *p) const noexcept { X509_NAME_free(p); } };
struct X509ExtDeleter { void operator()(X509_EXTENSION *p) const noexcept { X509_EXTENSION_free(p); } };
struct Asn1IntegerDeleter { void operator()(ASN1_INTEGER *p) const noexcept { ASN1_INTEGER_free(p); } };
struct BignumDeleter { void operator()(BIGNUM *p) const noexcept { BN_free(p); } };
struct SslCtxDeleter { void operator()(SSL_CTX *p) const noexcept { SSL_CTX_free(p); } };
struct SslDeleter { void operator()(SSL *p) const noexcept { SSL_free(p); } };
struct BioDeleter { void operator()(BIO *p) const noexcept { BIO_free(p); } };

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using X509ReqPtr = std::unique_ptr<X509_REQ, X509ReqDeleter>;
using X509NamePtr = std::unique_ptr<X509_NAME, X509NameDeleter>;
using X509ExtPtr = std::unique_ptr<X509_EXTENSION, X509ExtDeleter>;
using Asn1IntegerPtr = std::unique_ptr<ASN1_INTEGER, Asn1IntegerDeleter>;
using BignumPtr = std::unique_ptr<BIGNUM, BignumDeleter>;
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

class CertificateGenerator
{
public:
    CertificateGenerator() = delete;

    static bool generateCaCertificate(CertAlgorithm alg, const std::string &certPath, const std::string &keyPath);
    static X509ReqPtr createServerCsr(CertAlgorithm alg, const std::string &reqPath = {}, const std::string &keyPath = {});
    static bool createServerCertificate(X509_REQ *csr, CertAlgorithm alg, const std::string &caCertPath, const std::string &caKeyPath, const std::string &serverCertPath);
    static bool generateServerCertificateChain(CertAlgorithm alg, const std::string &caCertPath, const std::string &caKeyPath, const std::string &serverReqPath, const std::string &serverKeyPath, const std::string &serverCertPath);

    static X509Ptr loadCertificate(const std::string &certPath);
    static EvpPkeyPtr loadPrivateKey(const std::string &keyPath);
    static EvpPkeyPtr extractPublicKey(X509 *cert);

    static bool benchmarkSignAndVerify(X509_REQ *csr, CertAlgorithm alg, X509 *caCert, EVP_PKEY *caPublicKey, EVP_PKEY *caPrivateKey, long long &signTimeUs, long long &verifyTimeUs);

private:
    static EvpPkeyPtr generateKey(CertAlgorithm alg);
    static bool addExtension(X509 *cert, int nid, const char *value, X509 *issuer = nullptr);
    static bool generateRandomSerial(ASN1_INTEGER *serial);
    static X509Ptr buildUnsignedServerCertificate(X509_REQ *csr, X509 *caCert);
    static int signCertificate(X509 *cert, EVP_PKEY *privateKey, CertAlgorithm alg);
    static bool writePrivateKeyPem(EVP_PKEY *pkey, const std::string &path);
    static bool writeCertificatePem(X509 *cert, const std::string &path);
    static bool writeCsrPem(X509_REQ *req, const std::string &path);
};

class TlsContext
{
public:
    TlsContext(const TlsContext &) = delete;
    TlsContext &operator=(const TlsContext &) = delete;
    TlsContext(TlsContext &&) noexcept = default;
    TlsContext &operator=(TlsContext &&) noexcept = default;
    ~TlsContext() = default;

    static void initializeOpenSsl();
    static std::unique_ptr<TlsContext> createServerContext(const std::string &cipherSuite);
    static std::unique_ptr<TlsContext> createClientContext(bool enableKeylog);

    bool loadCertificateAndKey(const std::string &certPath, const std::string &keyPath);
    SSL_CTX *nativeHandle() const noexcept { return m_ctx.get(); }

private:
    explicit TlsContext(SslCtxPtr ctx);
    static void keylogCallback(const SSL *ssl, const char *line);

    SslCtxPtr m_ctx;
};

struct PeerCertificateInfo
{
    bool valid = false;
    std::string subject;
    std::string issuer;
    long version = 0;
    std::string publicKeyAlgorithm;
    int publicKeyBits = 0;
    bool showPublicKeyBits = false;
    std::string signatureAlgorithm;
};

enum class HandshakeStatus
{
    InProgress,
    Completed,
    Failed
};

class TlsSession
{
public:
    TlsSession(const TlsContext &context, bool isServer);
    TlsSession(const TlsSession &) = delete;
    TlsSession &operator=(const TlsSession &) = delete;
    TlsSession(TlsSession &&) noexcept = default;
    TlsSession &operator=(TlsSession &&) noexcept = default;
    ~TlsSession();

    static bool createConnectedPair(const TlsContext &clientCtx, const TlsContext &serverCtx, std::unique_ptr<TlsSession> &clientSession, std::unique_ptr<TlsSession> &serverSession);
    static bool performInMemoryHandshake(TlsSession &clientSession, TlsSession &serverSession, long long &handshakeTimeUs);

    bool isValid() const noexcept { return m_ssl != nullptr; }
    bool isServer() const noexcept { return m_isServer; }
    bool isHandshakeCompleted() const noexcept { return m_handshakeCompleted; }

    HandshakeStatus stepHandshake(int *outSslError = nullptr);

    void feedIncomingData(const char *data, int size);
    std::vector<char> takeOutgoingData();

    int sendApplicationData(const char *data, int size);
    int receiveApplicationData(char *buf, int maxSize);

    PeerCertificateInfo peerCertificateInfo() const;

private:
    TlsSession(SslPtr ssl, BioPtr networkBio, bool isServer);

    SslPtr m_ssl;
    BioPtr m_networkBio;
    bool m_isServer = false;
    bool m_handshakeCompleted = false;
};

#endif // CRYPTO_H
