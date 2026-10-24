#include "benchmark.h"
#include "ui_benchmark.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <numeric>

#include <QDir>
#include <QMetaType>

using namespace std::chrono;

namespace {

void removeBenchTempFiles()
{
    std::remove("cert/test-ca-cert.pem");
    std::remove("cert/test-ca-key.pem");
    std::remove("cert/bench-ca-cert.pem");
    std::remove("cert/bench-ca-key.pem");
    std::remove("cert/bench-server-cert.pem");
    std::remove("cert/bench-server-key.pem");
    std::remove("cert/bench-server-req.pem");
}

} // namespace

// ============================================================================
// BenchmarkWorker
// ============================================================================

BenchmarkWorker::BenchmarkWorker(const BenchmarkConfig &config, QObject *parent)
    : QObject(parent)
    , m_config(config)
{
}

bool BenchmarkWorker::sendAndReceiveMessage(TlsSession &sslClient, TlsSession &sslServer)
{
    char someData[kMessageSize * 2] = {};

    if (sslClient.sendApplicationData(someData, kMessageSize) != kMessageSize)
        return false;

    if (sslServer.receiveApplicationData(someData, kMessageSize * 2) != kMessageSize)
        return false;

    return true;
}

QList<long long> BenchmarkWorker::computeStatistics(QList<long long> measurements)
{
    QList<long long> result;

    if (measurements.empty())
    {
        result << 0 << 0 << 0 << 0 << 0 << 0;
        return result;
    }

    std::sort(measurements.begin(), measurements.end());
    long long sum = std::accumulate(measurements.begin(), measurements.end(), 0LL);

    result << measurements.first();
    result << sum / measurements.count();
    result << measurements[measurements.count() / 2];
    result << measurements[measurements.count() * 9 / 10];
    result << measurements[measurements.count() * 99 / 100];
    result << measurements.last();

    return result;
}

void BenchmarkWorker::process()
{
    const long totalActions = m_config.certSignAttempts * 2 + m_config.handshakeAttempts + kMessageExchangeSessions;
    long performed = 0;
    int lastPercent = -1;

    auto updateProgress = [&](long delta) {
        performed += delta;
        if (totalActions > 0)
        {
            int percent = static_cast<int>(100 * performed / totalActions);
            if (percent != lastPercent)
            {
                lastPercent = percent;
                emit progressUpdated(percent);
            }
        }
    };

    auto isInterrupted = []() {
        QThread *thr = QThread::currentThread();
        return thr && thr->isInterruptionRequested();
    };

    QDir().mkpath("cert");

    // 1 - Скорость создания и проверки подписи
    const std::string caCertPath = "cert/test-ca-cert.pem";
    const std::string caKeyPath = "cert/test-ca-key.pem";

    if (!CertificateGenerator::generateCaCertificate(m_config.certAlgorithm, caCertPath, caKeyPath))
    {
        removeBenchTempFiles();
        emit errorOccurred("Не удалось создать сертификат ЦС");
        return;
    }

    X509ReqPtr x509req = CertificateGenerator::createServerCsr(m_config.certAlgorithm);
    if (!x509req)
    {
        removeBenchTempFiles();
        emit errorOccurred("Не удалось создать сертификат запроса");
        return;
    }

    X509Ptr caCert = CertificateGenerator::loadCertificate(caCertPath);
    EvpPkeyPtr caPublicKey = CertificateGenerator::extractPublicKey(caCert.get());
    EvpPkeyPtr caPrivateKey = CertificateGenerator::loadPrivateKey(caKeyPath);

    if (!caCert || !caPublicKey || !caPrivateKey)
    {
        removeBenchTempFiles();
        emit errorOccurred("Не удалось открыть сертификат или ключ ЦС");
        return;
    }

    QList<long long> certSignMeasurements;
    QList<long long> certVerifyMeasurements;
    long long timeSignMicrosec = 0;
    long long timeVerifyMicrosec = 0;

    int certSignSucceeded = static_cast<int>(m_config.certSignAttempts);
    int certVerifySucceeded = static_cast<int>(m_config.certSignAttempts);

    for (long i = 0; i < m_config.certSignAttempts; i++)
    {
        if (isInterrupted())
        {
            removeBenchTempFiles();
            return;
        }

        if (!CertificateGenerator::benchmarkSignAndVerify(
                x509req.get(),
                m_config.certAlgorithm,
                caCert.get(),
                caPublicKey.get(),
                caPrivateKey.get(),
                timeSignMicrosec,
                timeVerifyMicrosec))
        {
            --certSignSucceeded;
        }
        else
        {
            certSignMeasurements << timeSignMicrosec;
        }

        if (timeVerifyMicrosec == 0)
            --certVerifySucceeded;
        else
            certVerifyMeasurements << timeVerifyMicrosec;

        updateProgress(2);
    }

    std::remove(caCertPath.c_str());
    std::remove(caKeyPath.c_str());

    // 2 - скорость установления хендшейка и обмена
    if (!CertificateGenerator::generateServerCertificateChain(
            m_config.certAlgorithm,
            "cert/bench-ca-cert.pem",
            "cert/bench-ca-key.pem",
            "cert/bench-server-req.pem",
            "cert/bench-server-key.pem",
            "cert/bench-server-cert.pem"))
    {
        removeBenchTempFiles();
        emit errorOccurred("Не удалось создать сертификат серверу!");
        return;
    }

    std::unique_ptr<TlsContext> sslServerCtx = TlsContext::createServerContext(m_config.cipherSuite);
    if (!sslServerCtx)
    {
        removeBenchTempFiles();
        emit errorOccurred("Не удалось создать контекст SSL!");
        return;
    }

    if (!sslServerCtx->loadCertificateAndKey("cert/bench-server-cert.pem", "cert/bench-server-key.pem"))
    {
        removeBenchTempFiles();
        emit errorOccurred("Не удалось загрузить сертификат сервера!");
        return;
    }

    std::unique_ptr<TlsContext> sslClientCtx = TlsContext::createClientContext(false);
    if (!sslClientCtx)
    {
        removeBenchTempFiles();
        emit errorOccurred("Не удалось создать контекст SSL!");
        return;
    }

    QList<long long> handshakeMeasurements;
    long long timeHandshake = 0;
    int handshakeSucceeded = static_cast<int>(m_config.handshakeAttempts);

    for (long i = 0; i < m_config.handshakeAttempts; i++)
    {
        if (isInterrupted())
        {
            removeBenchTempFiles();
            return;
        }

        std::unique_ptr<TlsSession> sslClient;
        std::unique_ptr<TlsSession> sslServer;

        if (!TlsSession::createConnectedPair(*sslClientCtx, *sslServerCtx, sslClient, sslServer)
                || !TlsSession::performInMemoryHandshake(*sslClient, *sslServer, timeHandshake))
        {
            --handshakeSucceeded;
        }
        else
        {
            handshakeMeasurements << timeHandshake;
        }

        updateProgress(1);
    }

    // 3 - время обмена
    QList<long long> msgExchangeMeasurements;
    long long timeExchange = 0;

    for (int iSession = 0; iSession < kMessageExchangeSessions; iSession++)
    {
        if (isInterrupted())
        {
            removeBenchTempFiles();
            return;
        }

        std::unique_ptr<TlsSession> sslClient;
        std::unique_ptr<TlsSession> sslServer;

        if (!TlsSession::createConnectedPair(*sslClientCtx, *sslServerCtx, sslClient, sslServer)
                || !TlsSession::performInMemoryHandshake(*sslClient, *sslServer, timeHandshake))
        {
            updateProgress(1);
            continue;
        }

        bool sessionOk = true;
        auto start = high_resolution_clock::now();

        for (long i = 0; i < m_config.messagesToSend; i++)
        {
            if ((i & 0x3FF) == 0 && isInterrupted())
            {
                removeBenchTempFiles();
                return;
            }

            if (!sendAndReceiveMessage(*sslClient, *sslServer))
            {
                sessionOk = false;
                break;
            }
        }

        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        timeExchange = timeHandshake + duration.count();

        updateProgress(1);

        if (sessionOk)
            msgExchangeMeasurements << timeExchange;
    }

    removeBenchTempFiles();

    BenchmarkResult result;
    result.certSignSucceeded = certSignSucceeded;
    result.certVerifySucceeded = certVerifySucceeded;
    result.handshakeSucceeded = handshakeSucceeded;
    result.messagesToSend = m_config.messagesToSend;
    result.certSignStats = computeStatistics(certSignMeasurements);
    result.certVerifyStats = computeStatistics(certVerifyMeasurements);
    result.handshakeStats = computeStatistics(handshakeMeasurements);
    result.msgExchangeStats = computeStatistics(msgExchangeMeasurements);

    emit finished(result);
}

// ============================================================================
// Benchmark
// ============================================================================

Benchmark::Benchmark(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Benchmark)
{
    qRegisterMetaType<BenchmarkResult>("BenchmarkResult");
    ui->setupUi(this);

    resetTable();
}

Benchmark::~Benchmark()
{
    stopWorkerThread();
    delete ui;
}

void Benchmark::closeEvent(QCloseEvent *event)
{
    stopWorkerThread();
    emit Closed();
    event->accept();
}

void Benchmark::stopWorkerThread()
{
    if (m_workerThread)
    {
        m_workerThread->requestInterruption();
        m_workerThread->quit();
        m_workerThread->wait();
        delete m_workerThread;
        m_workerThread = nullptr;
    }
}

void Benchmark::setControlsEnabled(bool enabled)
{
    ui->pushButton->setEnabled(enabled);
    ui->spinBox->setEnabled(enabled);
    ui->spinBox_2->setEnabled(enabled);
    ui->spinBox_3->setEnabled(enabled);
    ui->groupBox->setEnabled(enabled);
}

void Benchmark::resetTable()
{
    for (int i = 0; i < ui->tableWidget->rowCount(); i++)
    {
        for (int j = 0; j < ui->tableWidget->columnCount(); j++)
        {
            ui->tableWidget->setItem(i, j, new QTableWidgetItem("0"));
        }
    }

    ui->spinBox->setValue(m_certSignAttempts);
    ui->spinBox_2->setValue(m_handshakeAttempts);
    ui->spinBox_3->setValue(m_messagesToSend);
    ui->lineEdit_4->setText("0");
    ui->progressBar->setValue(0);
}

void Benchmark::startBench()
{
    stopWorkerThread();

    BenchmarkConfig config;
    if (ui->radioButton->isChecked())
        config.cipherSuite = "TLS_AES_256_GCM_SHA384";
    else if (ui->radioButton_2->isChecked())
        config.cipherSuite = "TLS_CHACHA20_POLY1305_SHA256";
    else if (ui->radioButton_3->isChecked())
        config.cipherSuite = "TLS_AES_128_GCM_SHA256";

    if (ui->radioButton_5->isChecked())
        config.certAlgorithm = CertAlgorithm::Rsa;
    else if (ui->radioButton_4->isChecked())
        config.certAlgorithm = CertAlgorithm::Ecdsa;
    else if (ui->radioButton_6->isChecked())
        config.certAlgorithm = CertAlgorithm::Ed25519;

    config.certSignAttempts = m_certSignAttempts;
    config.handshakeAttempts = m_handshakeAttempts;
    config.messagesToSend = m_messagesToSend;

    m_workerThread = new QThread(this);
    BenchmarkWorker *worker = new BenchmarkWorker(config);
    worker->moveToThread(m_workerThread);

    connect(m_workerThread, &QThread::started, worker, &BenchmarkWorker::process);
    connect(worker, &BenchmarkWorker::progressUpdated, this, &Benchmark::onBenchmarkProgress);
    connect(worker, &BenchmarkWorker::finished, this, &Benchmark::onBenchmarkFinished);
    connect(worker, &BenchmarkWorker::errorOccurred, this, &Benchmark::onBenchmarkError);
    connect(m_workerThread, &QThread::finished, worker, &QObject::deleteLater);

    setControlsEnabled(false);
    m_workerThread->start();
}

void Benchmark::onBenchmarkProgress(int percent)
{
    ui->progressBar->setValue(percent);
}

void Benchmark::onBenchmarkFinished(const BenchmarkResult &result)
{
    stopWorkerThread();

    ui->spinBox->setValue(result.certSignSucceeded);
    ui->spinBox_2->setValue(result.handshakeSucceeded);
    ui->spinBox_3->setValue(result.messagesToSend);
    ui->lineEdit_4->setText(QString::number(result.messagesToSend * BenchmarkWorker::kMessageSize / 1024) + " КБ");
    ui->progressBar->setValue(100);

    for (int i = 0; i < 6; i++)
    {
        ui->tableWidget->setItem(0, i, new QTableWidgetItem(QString::number(static_cast<double>(result.certSignStats[i]) / 1000.0)));
        ui->tableWidget->setItem(1, i, new QTableWidgetItem(QString::number(static_cast<double>(result.certVerifyStats[i]) / 1000.0)));
        ui->tableWidget->setItem(2, i, new QTableWidgetItem(QString::number(static_cast<double>(result.handshakeStats[i]) / 1000.0)));
        ui->tableWidget->setItem(3, i, new QTableWidgetItem(QString::number(static_cast<double>(result.msgExchangeStats[i]) / 1000000.0)));
    }

    setControlsEnabled(true);
}

void Benchmark::onBenchmarkError(const QString &message)
{
    stopWorkerThread();
    QMessageBox::critical(this, "Ошибка", message);
    setControlsEnabled(true);
}

void Benchmark::on_pushButton_clicked()
{
    resetTable();
    startBench();
}

void Benchmark::on_spinBox_valueChanged(int arg1)
{
    m_certSignAttempts = arg1;
}

void Benchmark::on_spinBox_2_valueChanged(int arg1)
{
    m_handshakeAttempts = arg1;
}

void Benchmark::on_spinBox_3_valueChanged(int arg1)
{
    m_messagesToSend = arg1;
}
