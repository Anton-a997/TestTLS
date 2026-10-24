#include "benchmark.h"
#include "ui_benchmark.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <numeric>

#include <QDir>

using namespace std::chrono;

Benchmark::Benchmark(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Benchmark)
{
    ui->setupUi(this);

    ResetTable();
}

Benchmark::~Benchmark()
{
    delete ui;
}

void Benchmark::closeEvent(QCloseEvent *event)
{
    emit Closed();
    event->accept();
}

void Benchmark::ResetTable()
{
    for (int i = 0; i < ui->tableWidget->rowCount(); i++)
    {
        for (int j = 0; j < ui->tableWidget->columnCount(); j++)
        {
            ui->tableWidget->setItem(i, j, new QTableWidgetItem("0"));
        }
    }

    ui->spinBox->setValue(CERT_SIGN_ATTEMPTS);
    ui->spinBox_2->setValue(HANDSHAKE_ATTEMPTS);
    ui->spinBox_3->setValue(MESSAGES_TO_SEND);
    ui->lineEdit_4->setText("0");
    ui->progressBar->setValue(0);
}

void Benchmark::StartBench()
{
    const char *alg_string = "";

    if (ui->radioButton->isChecked())
        alg_string = "TLS_AES_256_GCM_SHA384";
    else if (ui->radioButton_2->isChecked())
        alg_string = "TLS_CHACHA20_POLY1305_SHA256";
    else if (ui->radioButton_3->isChecked())
        alg_string = "TLS_AES_128_GCM_SHA256";

    CertAlgorithm cert_alg = CertAlgorithm::Rsa;

    if (ui->radioButton_5->isChecked())
        cert_alg = CertAlgorithm::Rsa;
    else if (ui->radioButton_4->isChecked())
        cert_alg = CertAlgorithm::Ecdsa;
    else if (ui->radioButton_6->isChecked())
        cert_alg = CertAlgorithm::Ed25519;

    int totalActions = CERT_SIGN_ATTEMPTS * 2 + HANDSHAKE_ATTEMPTS + MESSAGE_EXCHANGE_SESSIONS;
    int performed = 0;

    QDir().mkpath("cert");

    // 1 - Скорость создания и проверки подписи
    const std::string caCertPath = "cert/test-ca-cert.pem";
    const std::string caKeyPath = "cert/test-ca-key.pem";

    if (!CertificateGenerator::generateCaCertificate(cert_alg, caCertPath, caKeyPath))
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось создать сертификат ЦС");
        return;
    }

    X509ReqPtr x509req = CertificateGenerator::createServerCsr(cert_alg);
    if (!x509req)
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось создать сертификат запроса");
        return;
    }

    X509Ptr caCert = CertificateGenerator::loadCertificate(caCertPath);
    EvpPkeyPtr caPublicKey = CertificateGenerator::extractPublicKey(caCert.get());
    EvpPkeyPtr caPrivateKey = CertificateGenerator::loadPrivateKey(caKeyPath);

    if (!caCert || !caPublicKey || !caPrivateKey)
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть сертификат или ключ ЦС");
        return;
    }

    QList<long long> cert_sign_measurements, cert_verify_measurements;
    long long time_sign_microsec = 0;
    long long time_verify_microsec = 0;

    int cert_sign_succeeded = CERT_SIGN_ATTEMPTS;
    int cert_verify_succeeded = CERT_SIGN_ATTEMPTS;

    for (int i = 0; i < CERT_SIGN_ATTEMPTS; i++)
    {
        if (!CertificateGenerator::benchmarkSignAndVerify(
                x509req.get(),
                cert_alg,
                caCert.get(),
                caPublicKey.get(),
                caPrivateKey.get(),
                time_sign_microsec,
                time_verify_microsec))
        {
            --cert_sign_succeeded;
        }
        else
        {
            cert_sign_measurements << time_sign_microsec;
        }

        if (time_verify_microsec == 0)
            --cert_verify_succeeded;
        else
            cert_verify_measurements << time_verify_microsec;

        performed += 2;
        ui->progressBar->setValue(100 * performed / totalActions);
    }

    std::remove(caCertPath.c_str());
    std::remove(caKeyPath.c_str());

    ui->spinBox->setValue(cert_sign_succeeded);

    QList<long long> cert_sign_statistics = GetStatistics(cert_sign_measurements);
    QList<long long> cert_verify_statistics = GetStatistics(cert_verify_measurements);

    for (int i = 0; i < 6; i++)
    {
        ui->tableWidget->setItem(0, i, new QTableWidgetItem(QString::number(static_cast<double>(cert_sign_statistics[i]) / 1000.0)));
        ui->tableWidget->setItem(1, i, new QTableWidgetItem(QString::number(static_cast<double>(cert_verify_statistics[i]) / 1000.0)));
    }

    // 2 - скорость установления хендшейка и обмена
    if (!CertificateGenerator::generateServerCertificateChain(
            cert_alg,
            "cert/bench-ca-cert.pem",
            "cert/bench-ca-key.pem",
            "cert/bench-server-req.pem",
            "cert/bench-server-key.pem",
            "cert/bench-server-cert.pem"))
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось создать сертификат серверу!");
        return;
    }

    std::unique_ptr<TlsContext> ssl_server_ctx = TlsContext::createServerContext(alg_string);
    if (!ssl_server_ctx)
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось создать контекст SSL!");
        return;
    }

    if (!ssl_server_ctx->loadCertificateAndKey("cert/bench-server-cert.pem", "cert/bench-server-key.pem"))
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось загрузить сертификат сервера!");
        return;
    }

    std::unique_ptr<TlsContext> ssl_client_ctx = TlsContext::createClientContext(false);
    if (!ssl_client_ctx)
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось создать контекст SSL!");
        return;
    }

    QList<long long> handshake_measurements;
    long long time_handshake = 0;

    int handshake_succeeded = HANDSHAKE_ATTEMPTS;

    for (int i = 0; i < HANDSHAKE_ATTEMPTS; i++)
    {
        std::unique_ptr<TlsSession> ssl_client;
        std::unique_ptr<TlsSession> ssl_server;

        if (!TlsSession::createConnectedPair(*ssl_client_ctx, *ssl_server_ctx, ssl_client, ssl_server)
                || !TlsSession::performInMemoryHandshake(*ssl_client, *ssl_server, time_handshake))
        {
            --handshake_succeeded;
        }
        else
        {
            handshake_measurements << time_handshake;
        }

        performed += 1;
        ui->progressBar->setValue(100 * performed / totalActions);
    }

    ui->spinBox_2->setValue(handshake_succeeded);

    QList<long long> handshake_statistics = GetStatistics(handshake_measurements);

    for (int i = 0; i < 6; i++)
    {
        ui->tableWidget->setItem(2, i, new QTableWidgetItem(QString::number(static_cast<double>(handshake_statistics[i]) / 1000.0)));
    }

    // 3 - время обмена
    QList<long long> msg_exchange_measurements;
    long long time_exchange = 0;

    for (int iSession = 0; iSession < MESSAGE_EXCHANGE_SESSIONS; iSession++)
    {
        std::unique_ptr<TlsSession> ssl_client;
        std::unique_ptr<TlsSession> ssl_server;

        if (!TlsSession::createConnectedPair(*ssl_client_ctx, *ssl_server_ctx, ssl_client, ssl_server)
                || !TlsSession::performInMemoryHandshake(*ssl_client, *ssl_server, time_handshake))
        {
            continue;
        }

        bool session_ok = true;

        auto start = high_resolution_clock::now();

        for (int i = 0; i < MESSAGES_TO_SEND; i++)
        {
            if (!TLS_send_message(*ssl_client, *ssl_server))
            {
                session_ok = false;
                break;
            }
        }

        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        time_exchange = time_handshake + duration.count();

        performed += 1;
        ui->progressBar->setValue(100 * performed / totalActions);

        if (!session_ok)
            continue;

        msg_exchange_measurements << time_exchange;
    }

    ui->spinBox_3->setValue(MESSAGES_TO_SEND);
    ui->lineEdit_4->setText(QString::number(MESSAGES_TO_SEND * MESSAGE_SIZE / 1024) + " КБ");

    QList<long long> msg_exchange_statistics = GetStatistics(msg_exchange_measurements);

    for (int i = 0; i < 6; i++)
    {
        ui->tableWidget->setItem(3, i, new QTableWidgetItem(QString::number(static_cast<double>(msg_exchange_statistics[i]) / 1000000.0)));
    }

    std::remove("cert/bench-ca-cert.pem");
    std::remove("cert/bench-ca-key.pem");
    std::remove("cert/bench-server-cert.pem");
    std::remove("cert/bench-server-key.pem");
    std::remove("cert/bench-server-req.pem");
}

bool Benchmark::TLS_send_message(TlsSession &ssl_client, TlsSession &ssl_server)
{
    char some_data[MESSAGE_SIZE * 2] = {};

    if (ssl_client.sendApplicationData(some_data, MESSAGE_SIZE) != MESSAGE_SIZE)
        return false;

    if (ssl_server.receiveApplicationData(some_data, MESSAGE_SIZE * 2) != MESSAGE_SIZE)
        return false;

    return true;
}

QList<long long> Benchmark::GetStatistics(QList<long long> measurements)
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

void Benchmark::on_pushButton_clicked()
{
    ui->pushButton->setEnabled(false);
    ResetTable();
    StartBench();
    ui->pushButton->setEnabled(true);
    return;
}

void Benchmark::on_spinBox_valueChanged(int arg1)
{
    CERT_SIGN_ATTEMPTS = arg1;
}

void Benchmark::on_spinBox_2_valueChanged(int arg1)
{
    HANDSHAKE_ATTEMPTS = arg1;
}

void Benchmark::on_spinBox_3_valueChanged(int arg1)
{
    MESSAGES_TO_SEND = arg1;
}
