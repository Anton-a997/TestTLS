#include "crypto.h"

#include <chrono>
#include <cstdio>
#include <cstring>

namespace {

struct FileDeleter
{
    void operator()(FILE *f) const noexcept
    {
        if (f)
            std::fclose(f);
    }
};

using FilePtr = std::unique_ptr<FILE, FileDeleter>;

FilePtr openFile(const std::string &path, const char *mode)
{
#ifdef _MSC_VER
    FILE *f = nullptr;
    if (fopen_s(&f, path.c_str(), mode) != 0)
        return nullptr;
    return FilePtr(f);
#else
    return FilePtr(std::fopen(path.c_str(), mode));
#endif
}

constexpr const char *kDefaultSigAlgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:ed25519";
constexpr const char *kKeylogFilePath = "cert/keylog.log";

} // namespace

// ============================================================================
// CertificateGenerator
// ============================================================================

EvpPkeyPtr CertificateGenerator::generateKey(CertAlgorithm alg)
{
    EVP_PKEY *pkey = nullptr;

    switch (alg)
    {
    case CertAlgorithm::Rsa:
        pkey = EVP_RSA_gen(3072);
        break;
    case CertAlgorithm::Ecdsa:
        pkey = EVP_EC_gen("prime256v1");
        break;
    case CertAlgorithm::Ed25519:
        pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
        break;
    default:
        return nullptr;
    }

    if (!pkey)
        std::fprintf(stderr, "EVP_PKEY_Q_keygen failed\n");

    return EvpPkeyPtr(pkey);
}

bool CertificateGenerator::addExtension(X509 *cert, int nid, const char *value, X509 *issuer)
{
    if (!cert || !value)
        return false;

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer ? issuer : cert, cert, nullptr, nullptr, 0);

    X509ExtPtr ex(X509V3_EXT_conf_nid(nullptr, &ctx, nid, value));
    if (!ex)
        return false;

    return X509_add_ext(cert, ex.get(), -1) != 0;
}

bool CertificateGenerator::generateRandomSerial(ASN1_INTEGER *serial)
{
    if (!serial)
        return false;

    BignumPtr bn(BN_new());
    if (!bn)
        return false;

    if (!BN_rand(bn.get(), 64, 0, 0))
        return false;

    return BN_to_ASN1_INTEGER(bn.get(), serial) != nullptr;
}

int CertificateGenerator::signCertificate(X509 *cert, EVP_PKEY *privateKey, CertAlgorithm alg)
{
    if (!cert || !privateKey)
        return 0;

    switch (alg)
    {
    case CertAlgorithm::Rsa:
    case CertAlgorithm::Ecdsa:
        return X509_sign(cert, privateKey, EVP_sha256());
    case CertAlgorithm::Ed25519:
        return X509_sign(cert, privateKey, nullptr);
    default:
        return 0;
    }
}

bool CertificateGenerator::writePrivateKeyPem(EVP_PKEY *pkey, const std::string &path)
{
    FilePtr f = openFile(path, "wb");
    if (!f)
        return false;

    return PEM_write_PrivateKey(f.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr) != 0;
}

bool CertificateGenerator::writeCertificatePem(X509 *cert, const std::string &path)
{
    FilePtr f = openFile(path, "wb");
    if (!f)
        return false;

    return PEM_write_X509(f.get(), cert) != 0;
}

bool CertificateGenerator::writeCsrPem(X509_REQ *req, const std::string &path)
{
    FilePtr f = openFile(path, "wb");
    if (!f)
        return false;

    return PEM_write_X509_REQ(f.get(), req) != 0;
}

X509Ptr CertificateGenerator::loadCertificate(const std::string &certPath)
{
    FilePtr f = openFile(certPath, "r");
    if (!f)
        return nullptr;

    return X509Ptr(PEM_read_X509(f.get(), nullptr, nullptr, nullptr));
}

EvpPkeyPtr CertificateGenerator::loadPrivateKey(const std::string &keyPath)
{
    FilePtr f = openFile(keyPath, "r");
    if (!f)
        return nullptr;

    return EvpPkeyPtr(PEM_read_PrivateKey(f.get(), nullptr, nullptr, nullptr));
}

EvpPkeyPtr CertificateGenerator::extractPublicKey(X509 *cert)
{
    if (!cert)
        return nullptr;

    return EvpPkeyPtr(X509_get_pubkey(cert));
}

bool CertificateGenerator::generateCaCertificate(CertAlgorithm alg, const std::string &certPath, const std::string &keyPath)
{
    EvpPkeyPtr pkey = generateKey(alg);
    if (!pkey)
        return false;

    X509Ptr x509(X509_new());
    if (!x509)
        return false;

    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509.get()), 31536000L);
    X509_set_version(x509.get(), 2);

    if (!X509_set_pubkey(x509.get(), pkey.get()))
    {
        std::fprintf(stderr, "X509_set_pubkey failed\n");
        return false;
    }

    X509_NAME *name = X509_get_subject_name(x509.get());
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, reinterpret_cast<const unsigned char *>("UA"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, reinterpret_cast<const unsigned char *>("CA"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("CA"), -1, -1, 0);
    X509_set_issuer_name(x509.get(), name);

    if (!addExtension(x509.get(), NID_basic_constraints, "CA:TRUE")
            || !addExtension(x509.get(), NID_key_usage, "keyCertSign,cRLSign")
            || !addExtension(x509.get(), NID_subject_key_identifier, "hash")
            || !addExtension(x509.get(), NID_authority_key_identifier, "keyid:always"))
    {
        std::fprintf(stderr, "addExtension failed\n");
        return false;
    }

    if (signCertificate(x509.get(), pkey.get(), alg) <= 0)
    {
        std::fprintf(stderr, "X509_sign failed\n");
        return false;
    }

    if (!writePrivateKeyPem(pkey.get(), keyPath))
        return false;

    if (!writeCertificatePem(x509.get(), certPath))
        return false;

    return true;
}

X509ReqPtr CertificateGenerator::createServerCsr(CertAlgorithm alg, const std::string &reqPath, const std::string &keyPath)
{
    EvpPkeyPtr pkey = generateKey(alg);
    if (!pkey)
        return nullptr;

    X509ReqPtr x509req(X509_REQ_new());
    if (!x509req)
        return nullptr;

    X509_REQ_set_version(x509req.get(), 2);

    X509NamePtr name(X509_NAME_new());
    if (!name)
        return nullptr;

    X509_NAME_add_entry_by_txt(name.get(), "C",  MBSTRING_ASC, reinterpret_cast<const unsigned char *>("UA"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("TLS 1.3 Server"), -1, -1, 0);

    if (!X509_REQ_set_subject_name(x509req.get(), name.get()))
    {
        std::fprintf(stderr, "X509_REQ_set_subject_name failed\n");
        return nullptr;
    }

    if (!X509_REQ_set_pubkey(x509req.get(), pkey.get()))
    {
        std::fprintf(stderr, "X509_REQ_set_pubkey failed\n");
        return nullptr;
    }

    int err = 0;
    switch (alg)
    {
    case CertAlgorithm::Rsa:
    case CertAlgorithm::Ecdsa:
        err = X509_REQ_sign(x509req.get(), pkey.get(), EVP_sha256());
        break;
    case CertAlgorithm::Ed25519:
        err = X509_REQ_sign(x509req.get(), pkey.get(), nullptr);
        break;
    default:
        return nullptr;
    }

    if (err <= 0)
    {
        std::fprintf(stderr, "X509_REQ_sign failed\n");
        return nullptr;
    }

    if (!keyPath.empty() && !writePrivateKeyPem(pkey.get(), keyPath))
        return nullptr;

    if (!reqPath.empty() && !writeCsrPem(x509req.get(), reqPath))
        return nullptr;

    return x509req;
}

X509Ptr CertificateGenerator::buildUnsignedServerCertificate(X509_REQ *csr, X509 *caCert)
{
    if (!csr || !caCert)
        return nullptr;

    X509Ptr cert(X509_new());
    if (!cert)
        return nullptr;

    X509_set_version(cert.get(), 2);

    Asn1IntegerPtr serial(ASN1_INTEGER_new());
    if (!serial || !generateRandomSerial(serial.get()) || !X509_set_serialNumber(cert.get(), serial.get()))
        return nullptr;

    X509_set_issuer_name(cert.get(), X509_get_subject_name(caCert));
    X509_set_subject_name(cert.get(), X509_REQ_get_subject_name(csr));

    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0L);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 31536000L);

    EvpPkeyPtr reqPubKey(X509_REQ_get_pubkey(csr));
    if (!reqPubKey || !X509_set_pubkey(cert.get(), reqPubKey.get()))
        return nullptr;

    if (!addExtension(cert.get(), NID_key_usage, "digitalSignature", caCert)
            || !addExtension(cert.get(), NID_subject_key_identifier, "hash", caCert))
    {
        return nullptr;
    }

    return cert;
}

bool CertificateGenerator::createServerCertificate(X509_REQ *csr, CertAlgorithm alg, const std::string &caCertPath, const std::string &caKeyPath, const std::string &serverCertPath)
{
    X509Ptr caCert = loadCertificate(caCertPath);
    if (!caCert)
        return false;

    EvpPkeyPtr caPrivateKey = loadPrivateKey(caKeyPath);
    if (!caPrivateKey)
        return false;

    X509Ptr serverCert = buildUnsignedServerCertificate(csr, caCert.get());
    if (!serverCert)
        return false;

    if (signCertificate(serverCert.get(), caPrivateKey.get(), alg) <= 0)
        return false;

    return writeCertificatePem(serverCert.get(), serverCertPath);
}

bool CertificateGenerator::generateServerCertificateChain(CertAlgorithm alg, const std::string &caCertPath, const std::string &caKeyPath, const std::string &serverReqPath, const std::string &serverKeyPath, const std::string &serverCertPath)
{
    if (!generateCaCertificate(alg, caCertPath, caKeyPath))
        return false;

    X509ReqPtr csr = createServerCsr(alg, serverReqPath, serverKeyPath);
    if (!csr)
        return false;

    return createServerCertificate(csr.get(), alg, caCertPath, caKeyPath, serverCertPath);
}

bool CertificateGenerator::benchmarkSignAndVerify(X509_REQ *csr, CertAlgorithm alg, X509 *caCert, EVP_PKEY *caPublicKey, EVP_PKEY *caPrivateKey, long long &signTimeUs, long long &verifyTimeUs)
{
    using namespace std::chrono;

    if (!csr || !caCert || !caPublicKey || !caPrivateKey)
        return false;

    X509Ptr cert = buildUnsignedServerCertificate(csr, caCert);
    if (!cert)
        return false;

    auto start = high_resolution_clock::now();
    int signResult = signCertificate(cert.get(), caPrivateKey, alg);
    auto stop = high_resolution_clock::now();

    if (signResult <= 0)
        return false;

    signTimeUs = duration_cast<microseconds>(stop - start).count();

    start = high_resolution_clock::now();
    int verifyResult = X509_verify(cert.get(), caPublicKey);
    stop = high_resolution_clock::now();

    verifyTimeUs = (verifyResult > 0) ? duration_cast<microseconds>(stop - start).count() : 0;
    return true;
}

// ============================================================================
// TlsContext
// ============================================================================

TlsContext::TlsContext(SslCtxPtr ctx)
    : m_ctx(std::move(ctx))
{
}

void TlsContext::initializeOpenSsl()
{
    OPENSSL_init_ssl(0, nullptr);
}

std::unique_ptr<TlsContext> TlsContext::createServerContext(const std::string &cipherSuite)
{
    const SSL_METHOD *method = TLS_server_method();
    SslCtxPtr ctx(SSL_CTX_new(method));
    if (!ctx)
        return nullptr;

    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set1_sigalgs_list(ctx.get(), kDefaultSigAlgs);
    if (!cipherSuite.empty())
        SSL_CTX_set_ciphersuites(ctx.get(), cipherSuite.c_str());

    return std::unique_ptr<TlsContext>(new TlsContext(std::move(ctx)));
}

std::unique_ptr<TlsContext> TlsContext::createClientContext(bool enableKeylog)
{
    const SSL_METHOD *method = TLS_client_method();
    SslCtxPtr ctx(SSL_CTX_new(method));
    if (!ctx)
        return nullptr;

    std::remove(kKeylogFilePath);

    SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set1_sigalgs_list(ctx.get(), kDefaultSigAlgs);

    if (enableKeylog)
        SSL_CTX_set_keylog_callback(ctx.get(), &TlsContext::keylogCallback);

    return std::unique_ptr<TlsContext>(new TlsContext(std::move(ctx)));
}

bool TlsContext::loadCertificateAndKey(const std::string &certPath, const std::string &keyPath)
{
    if (!m_ctx)
        return false;

    if (SSL_CTX_use_certificate_file(m_ctx.get(), certPath.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(m_ctx.get(), keyPath.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}

void TlsContext::keylogCallback(const SSL * /*ssl*/, const char *line)
{
    if (!line)
        return;

    FilePtr f = openFile(kKeylogFilePath, "a");
    if (!f)
        return;

    std::fprintf(f.get(), "%s\n", line);
}

// ============================================================================
// TlsSession
// ============================================================================

TlsSession::TlsSession(const TlsContext &context, bool isServer)
    : m_isServer(isServer)
{
    if (!context.nativeHandle())
        return;

    SslPtr ssl(SSL_new(context.nativeHandle()));
    if (!ssl)
        return;

    BIO *internalBio = nullptr;
    BIO *networkBio = nullptr;
    if (!BIO_new_bio_pair(&internalBio, 0, &networkBio, 0))
        return;

    SSL_set_bio(ssl.get(), internalBio, internalBio);
    m_ssl = std::move(ssl);
    m_networkBio.reset(networkBio);
}

TlsSession::TlsSession(SslPtr ssl, BioPtr networkBio, bool isServer)
    : m_ssl(std::move(ssl))
    , m_networkBio(std::move(networkBio))
    , m_isServer(isServer)
{
}

TlsSession::~TlsSession()
{
    if (m_ssl)
        SSL_shutdown(m_ssl.get());
}

bool TlsSession::createConnectedPair(const TlsContext &clientCtx, const TlsContext &serverCtx, std::unique_ptr<TlsSession> &clientSession, std::unique_ptr<TlsSession> &serverSession)
{
    if (!clientCtx.nativeHandle() || !serverCtx.nativeHandle())
        return false;

    SslPtr clientSsl(SSL_new(clientCtx.nativeHandle()));
    SslPtr serverSsl(SSL_new(serverCtx.nativeHandle()));
    if (!clientSsl || !serverSsl)
        return false;

    BIO *clientBio = nullptr;
    BIO *serverBio = nullptr;
    if (!BIO_new_bio_pair(&clientBio, 0, &serverBio, 0))
        return false;

    SSL_set_bio(clientSsl.get(), clientBio, clientBio);
    SSL_set_bio(serverSsl.get(), serverBio, serverBio);

    clientSession.reset(new TlsSession(std::move(clientSsl), nullptr, false));
    serverSession.reset(new TlsSession(std::move(serverSsl), nullptr, true));
    return true;
}

bool TlsSession::performInMemoryHandshake(TlsSession &clientSession, TlsSession &serverSession, long long &handshakeTimeUs)
{
    using namespace std::chrono;

    if (!clientSession.isValid() || !serverSession.isValid())
        return false;

    auto start = high_resolution_clock::now();

    while (!clientSession.isHandshakeCompleted() || !serverSession.isHandshakeCompleted())
    {
        if (!clientSession.isHandshakeCompleted())
        {
            if (clientSession.stepHandshake() == HandshakeStatus::Failed)
                return false;
        }

        if (!serverSession.isHandshakeCompleted())
        {
            if (serverSession.stepHandshake() == HandshakeStatus::Failed)
                return false;
        }
    }

    auto stop = high_resolution_clock::now();
    handshakeTimeUs = duration_cast<microseconds>(stop - start).count();
    return true;
}

HandshakeStatus TlsSession::stepHandshake(int *outSslError)
{
    if (!m_ssl)
        return HandshakeStatus::Failed;

    if (m_handshakeCompleted)
        return HandshakeStatus::Completed;

    int status = m_isServer ? SSL_accept(m_ssl.get()) : SSL_connect(m_ssl.get());
    if (status == 1)
    {
        m_handshakeCompleted = true;
        return HandshakeStatus::Completed;
    }

    int err = SSL_get_error(m_ssl.get(), status);
    if (outSslError)
        *outSslError = err;

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return HandshakeStatus::InProgress;

    return HandshakeStatus::Failed;
}

void TlsSession::feedIncomingData(const char *data, int size)
{
    if (!m_networkBio || !data || size <= 0)
        return;

    BIO_write(m_networkBio.get(), data, size);
}

std::vector<char> TlsSession::takeOutgoingData()
{
    std::vector<char> output;
    if (!m_networkBio)
        return output;

    char buf[4096];
    int bread = 0;
    while ((bread = BIO_read(m_networkBio.get(), buf, sizeof(buf))) > 0)
    {
        output.insert(output.end(), buf, buf + bread);
    }

    return output;
}

int TlsSession::sendApplicationData(const char *data, int size)
{
    if (!m_ssl || !data || size <= 0)
        return 0;

    int len = SSL_write(m_ssl.get(), data, size);
    if (len < 0)
    {
        int err = SSL_get_error(m_ssl.get(), len);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -err;
    }

    return len;
}

int TlsSession::receiveApplicationData(char *buf, int maxSize)
{
    if (!m_ssl || !buf || maxSize <= 0)
        return 0;

    int len = 0;
    char *rdBuf = buf;

    while (static_cast<int>(rdBuf - buf) < maxSize)
    {
        len = SSL_read(m_ssl.get(), rdBuf, maxSize - static_cast<int>(rdBuf - buf));
        if (len > 0)
            rdBuf += len;
        else
            break;
    }

    int totalRead = static_cast<int>(rdBuf - buf);
    if (totalRead > 0)
        return totalRead;

    if (len <= 0)
    {
        int err = SSL_get_error(m_ssl.get(), len);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -err;
    }

    return totalRead;
}

PeerCertificateInfo TlsSession::peerCertificateInfo() const
{
    PeerCertificateInfo info;
    if (!m_ssl)
        return info;

    X509Ptr cert(SSL_get1_peer_certificate(m_ssl.get()));
    if (!cert)
        return info;

    info.valid = true;

    if (char *subj = X509_NAME_oneline(X509_get_subject_name(cert.get()), nullptr, 0))
    {
        info.subject = subj;
        OPENSSL_free(subj);
    }

    if (char *iss = X509_NAME_oneline(X509_get_issuer_name(cert.get()), nullptr, 0))
    {
        info.issuer = iss;
        OPENSSL_free(iss);
    }

    info.version = X509_get_version(cert.get()) + 1;

    EvpPkeyPtr pubkey(X509_get_pubkey(cert.get()));
    if (pubkey)
    {
        const char *typeName = EVP_PKEY_get0_type_name(pubkey.get());
        if (typeName)
            info.publicKeyAlgorithm = typeName;

        info.publicKeyBits = EVP_PKEY_bits(pubkey.get());
        info.showPublicKeyBits = (EVP_PKEY_get_base_id(pubkey.get()) != EVP_PKEY_ED25519);
    }

    const char *sigAlg = OBJ_nid2sn(X509_get_signature_nid(cert.get()));
    if (sigAlg)
        info.signatureAlgorithm = sigAlg;

    return info;
}
