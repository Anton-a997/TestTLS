#include "benchmark.h"
#include "ui_benchmark.h"

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
    char alg_string[256] = "";

    if (ui->radioButton->isChecked())
        snprintf(alg_string, 256 - strlen(alg_string), "%sTLS_AES_256_GCM_SHA384", alg_string);
    else if (ui->radioButton_2->isChecked())
        snprintf(alg_string, 256 - strlen(alg_string), "%sTLS_CHACHA20_POLY1305_SHA256", alg_string);
    else if (ui->radioButton_3->isChecked())
        snprintf(alg_string, 256 - strlen(alg_string), "%sTLS_AES_128_GCM_SHA256", alg_string);

    int cert_alg = 0;

    if (ui->radioButton_5->isChecked())
        cert_alg = CERT_RSA;
    else if (ui->radioButton_4->isChecked())
        cert_alg = CERT_ECDSA;
    else if (ui->radioButton_6->isChecked())
        cert_alg = CERT_ED25519;

    int totalActions = CERT_SIGN_ATTEMPTS * 2 + HANDSHAKE_ATTEMPTS + MESSAGE_EXCHANGE_SESSIONS;
    int performed = 0;

    // 1 - Скорость создания и проверки подписи
    if (!b_create_ca_cert(cert_alg))
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось создать сертификат ЦС");
        return;
    }

    X509_REQ* x509req = b_create_server_req(cert_alg);

    if (!x509req)
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось создать сертификат запроса");
        return;
    }

    const char p_ca_cert_path[] = "cert\\test-ca-cert.pem";
    const char p_ca_key_path[] = "cert\\test-ca-key.pem";

    FILE *p_ca_cert_file = NULL;
    FILE *p_ca_key_file = NULL;

    if (fopen_s(&p_ca_cert_file, p_ca_cert_path, "r") != 0)
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть сертификат ЦС");
        return;
    }

    if (fopen_s(&p_ca_key_file, p_ca_key_path, "r") != 0)
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть ключ ЦС");
        fclose(p_ca_cert_file);
        return;
    }

    QList<long long> cert_sign_measurements, cert_verify_measurements;
    long long time_sign_microsec, time_verify_microsec;

    int cert_sign_succeeded = CERT_SIGN_ATTEMPTS;
    int cert_verify_succeeded = CERT_SIGN_ATTEMPTS;

    for (int i = 0; i < CERT_SIGN_ATTEMPTS; i++)
    {
        fseek(p_ca_cert_file, 0, SEEK_SET);
        fseek(p_ca_key_file, 0, SEEK_SET);

        if (!b_create_server_cert(x509req, cert_alg, p_ca_cert_file, p_ca_key_file, time_sign_microsec, time_verify_microsec))
            --cert_sign_succeeded;
        else
            cert_sign_measurements << time_sign_microsec;

        if (time_verify_microsec == 0)
            --cert_verify_succeeded;
        else
            cert_verify_measurements << time_verify_microsec;

        performed += 2;
        ui->progressBar->setValue(100 * performed / totalActions);
    }

    fclose(p_ca_cert_file);
    fclose(p_ca_key_file);

    X509_REQ_free(x509req);

    remove("cert\\test-ca-cert.pem");
    remove("cert\\test-ca-key.pem");

    ui->spinBox->setValue(cert_sign_succeeded);

    QList<long long> cert_sign_statistics = GetStatistics(cert_sign_measurements);
    QList<long long> cert_verify_statistics = GetStatistics(cert_verify_measurements);

    for (int i = 0; i < 6; i++)
    {
        ui->tableWidget->setItem(0, i, new QTableWidgetItem(QString::number((double)cert_sign_statistics[i] / 1000)));
        ui->tableWidget->setItem(1, i, new QTableWidgetItem(QString::number((double)cert_verify_statistics[i] / 1000)));
    }

    // 2 - скорость установления хендшейка и обмена
    x509req = NULL;

    if (!create_ca_cert(cert_alg, "cert\\bench-ca-cert.pem", "cert\\bench-ca-key.pem")
            || (x509req = create_server_req(cert_alg, "cert\\bench-server-req.pem", "cert\\bench-server-key.pem")) == NULL
            || !create_server_cert(x509req, cert_alg, "cert\\bench-ca-cert.pem", "cert\\bench-ca-key.pem", "cert\\bench-server-cert.pem"))
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось создать сертификат серверу!");
        return;
    }

    X509_REQ_free(x509req);

    SSL_CTX* ssl_server_ctx = create_server_context(alg_string);

    if (!ssl_server_ctx)
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось создать контекст SSL!");
        return;
    }

    if (!load_server_cert(ssl_server_ctx, "cert\\bench-server-cert.pem", "cert\\bench-server-key.pem"))
    {
        SSL_CTX_free(ssl_server_ctx);
        QMessageBox::critical(this, "Ошибка", "Не удалось загрузить сертификат сервера!");
        return;
    }

    SSL_CTX* ssl_client_ctx = create_client_context(false);

    if (!ssl_client_ctx)
    {
        SSL_CTX_free(ssl_server_ctx);
        QMessageBox::critical(this, "Ошибка", "Не удалось создать контекст SSL!");
        return;
    }

    QList<long long> handshake_measurements;
    long long time_handshake = 0;

    int handshake_succeeded = HANDSHAKE_ATTEMPTS;

    for (int i = 0; i < HANDSHAKE_ATTEMPTS; i++)
    {
        SSL* ssl_client = SSL_new(ssl_client_ctx);
        SSL* ssl_server = SSL_new(ssl_server_ctx);

        BIO *client_bio;
        BIO *server_bio;

        BIO_new_bio_pair(&client_bio, 0, &server_bio, 0);
        SSL_set_bio(ssl_client, client_bio, client_bio);
        SSL_set_bio(ssl_server, server_bio, server_bio);

        if (!TLS_Handshake(ssl_client, ssl_server, time_handshake))
            --handshake_succeeded;
        else
            handshake_measurements << time_handshake;

        SSL_shutdown(ssl_client);
        SSL_free(ssl_client);
        SSL_shutdown(ssl_server);
        SSL_free(ssl_server);

        performed += 1;
        ui->progressBar->setValue(100 * performed / totalActions);
    }

    ui->spinBox_2->setValue(handshake_succeeded);

    QList<long long> handshake_statistics = GetStatistics(handshake_measurements);

    for (int i = 0; i < 6; i++)
    {
        ui->tableWidget->setItem(2, i, new QTableWidgetItem(QString::number((double)handshake_statistics[i] / 1000)));
    }

    // 3 - время обмена
    QList<long long> msg_exchange_measurements;
    long long time_exchange = 0;

    for (int iSession = 0; iSession < MESSAGE_EXCHANGE_SESSIONS; iSession++)
    {
        SSL* ssl_client = SSL_new(ssl_client_ctx);
        SSL* ssl_server = SSL_new(ssl_server_ctx);

        BIO *client_bio;
        BIO *server_bio;

        BIO_new_bio_pair(&client_bio, 0, &server_bio, 0);
        SSL_set_bio(ssl_client, client_bio, client_bio);
        SSL_set_bio(ssl_server, server_bio, server_bio);

        if (!TLS_Handshake(ssl_client, ssl_server, time_handshake))
            continue;

        bool session_ok = true;

        steady_clock::time_point start, stop;
        start = high_resolution_clock::now();

        for (int i = 0; i < MESSAGES_TO_SEND; i++)
        {
            if (!TLS_send_message(ssl_client, ssl_server))
            {
                session_ok = false;
                break;
            }
        }

        stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        time_exchange = time_handshake + duration.count();

        SSL_shutdown(ssl_client);
        SSL_free(ssl_client);
        SSL_shutdown(ssl_server);
        SSL_free(ssl_server);

        performed += 1;
        ui->progressBar->setValue(100 * performed / totalActions);

        if (!session_ok)
            continue;

        msg_exchange_measurements << time_exchange;
    }

    SSL_CTX_free(ssl_client_ctx);
    SSL_CTX_free(ssl_server_ctx);

    ui->spinBox_3->setValue(MESSAGES_TO_SEND);
    ui->lineEdit_4->setText(QString::number(MESSAGES_TO_SEND * MESSAGE_SIZE / 1024) + " КБ");

    QList<long long> msg_exchange_statistics = GetStatistics(msg_exchange_measurements);

    for (int i = 0; i < 6; i++)
    {
        ui->tableWidget->setItem(3, i, new QTableWidgetItem(QString::number((double)(msg_exchange_statistics[i] / 1000) / 1000)));
    }

    remove("cert\\bench-ca-cert.pem");
    remove("cert\\bench-ca-key.pem");
    remove("cert\\bench-server-cert.pem");
    remove("cert\\bench-server-key.pem");
    remove("cert\\bench-server-req.pem");
}

bool Benchmark::TLS_Handshake(SSL* ssl_client, SSL* ssl_server, long long &time_handshake)
{
    steady_clock::time_point start, stop;

    bool tls_connect = false;
    bool tls_accept = false;

    start = high_resolution_clock::now();

    while (!tls_accept || !tls_connect)
    {
        if (!tls_connect)
        {
            int status = 0;
            status = SSL_connect(ssl_client);

            if (status <= 0)
            {
                int err = SSL_get_error(ssl_client, status);

                if (err != SSL_ERROR_WANT_READ)
                {
                    return false;
                }
            }
            else
            {
                tls_connect = true;
            }
        }

        if (!tls_accept)
        {
            int status = 0;
            status = SSL_accept(ssl_server);

            if (status <= 0)
            {
                int err = SSL_get_error(ssl_server, status);

                if (err != SSL_ERROR_WANT_READ)
                {
                    return false;
                }
            }
            else
            {
                tls_accept = true;
            }
        }
    }

    stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    time_handshake = duration.count();

    return true;
}

bool Benchmark::TLS_send_message(SSL *ssl_client, SSL *ssl_server)
{
    char some_data[MESSAGE_SIZE * 2];

    if (tls_send_packet(ssl_client, some_data, MESSAGE_SIZE) != MESSAGE_SIZE)
        return false;

    tls_recv_packet(ssl_server, some_data, MESSAGE_SIZE * 2);

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
    long long sum = std::accumulate(measurements.begin(), measurements.end(), 0);

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
