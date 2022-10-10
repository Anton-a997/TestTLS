#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);

    system("mkdir cert");

    init_openssl();
}

Widget::~Widget()
{
    if (tcp_server)
    {
        tcp_server->close();
        delete tcp_server;
    }

    if (ssl_server_ctx)
        SSL_CTX_free(ssl_server_ctx);

    if (ssl_client_ctx)
        SSL_CTX_free(ssl_client_ctx);

    X509* server_crt;
    FILE* f;

    fopen_s(&f, "cert\\server-cert.pem", "r");

    if ((server_crt = PEM_read_X509(f, NULL, 0, NULL)) != NULL)
        fclose(f);

    cleanup_openssl();

    delete ui;
}

void Widget::on_pushButton_clicked()
{
    ConnectToIP();
}

void Widget::slotClientConnected()
{
    QTcpSocket *tcp_socket = tcp_server->nextPendingConnection();
    qint32 ip = tcp_socket->peerAddress().toIPv4Address();
    unsigned char *c_ip = (unsigned char*)&ip;
    ui->label->setText(QString("Входящее соединение от клиента ") + QString::number(c_ip[3]) + "." + QString::number(c_ip[2]) + "." + QString::number(c_ip[1]) + "." + QString::number(c_ip[0]));
    ChatDialog *chat_dialog = new ChatDialog(tcp_socket, true, ssl_server_ctx);
    chat_dialog->show();
    //connect(tcp_socket, SIGNAL(readyRead()), this, SLOT(slotReadClient()));
}

bool Widget::StartServer()
{
    char alg_string[256] = "";

    // выбор алгоритма шифрования на сессию
    if (ui->radioButton->isChecked())
        snprintf(alg_string, 256 - strlen(alg_string), "%sTLS_AES_256_GCM_SHA384", alg_string);
    else if (ui->radioButton_2->isChecked())
        snprintf(alg_string, 256 - strlen(alg_string), "%sTLS_CHACHA20_POLY1305_SHA256", alg_string);
    else if (ui->radioButton_3->isChecked())
        snprintf(alg_string, 256 - strlen(alg_string), "%sTLS_AES_128_GCM_SHA256", alg_string);

    // создания контекста SSL для сервера
    ssl_server_ctx = create_server_context(alg_string);

    if (!ssl_server_ctx)
    {
        ui->label->setText("Не удалось создать контекст SSL");
        return false;
    }

    // загрузка сертификатов сервера
    if (!load_server_cert(ssl_server_ctx, "cert\\server-cert.pem", "cert\\server-key.pem"))
    {
        if (ssl_server_ctx)
            SSL_CTX_free(ssl_server_ctx);

        ui->label->setText("Не удалось загрузить сертификат и ключ сервера!");
        return false;
    }

    // запуск сервера
    tcp_server = new QTcpServer(this);
    connect(tcp_server, SIGNAL(newConnection()), this, SLOT(slotClientConnected()));

    if (!tcp_server->listen(QHostAddress::Any, 13337))
    {
        if (ssl_server_ctx)
            SSL_CTX_free(ssl_server_ctx);

        ui->label->setText(QObject::tr("Не удалось запустить сервер: %1.").arg(tcp_server->errorString()));
        return false;
    }
    else
    {
        ui->label->setText("Ожидание подключения клиента...");
    }

    return true;
}

void Widget::ConnectToIP()
{
    QString str_ip = ui->lineEdit->text();
    str_ip.remove(' ');

    QTcpSocket *tcp_socket = new QTcpSocket();
    tcp_socket->connectToHost(str_ip, 13337);

    if (!tcp_socket->waitForConnected())
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось установить соединение с сервером!");
    }
    else
    {
        ui->lineEdit->clear();
        ssl_client_ctx = create_client_context(true);

        if (!ssl_client_ctx)
        {
            QMessageBox::critical(this, "Ошибка", "Не удалось создать контекст SSL!");
            return;
        }

        ChatDialog *chat_dialog = new ChatDialog(tcp_socket, false, ssl_client_ctx);
        chat_dialog->show();
    }
}

void Widget::on_pushButton_2_clicked()
{
    if (StartServer())
        ui->pushButton_2->setEnabled(false);
}

void Widget::on_pushButton_3_clicked()
{
    // генерация сертификатов
    X509_REQ* req = NULL;
    bool ok = false;

    if (ui->radioButton_5->isChecked())
    {
        if (create_ca_cert(CERT_RSA, "cert\\ca-cert.pem", "cert\\ca-key.pem")) // если успешно создан сертификат ЦС
            if ((req = create_server_req(CERT_RSA, "cert\\server-req.pem", "cert\\server-key.pem")) != NULL) // и если успешно создан сертификат запроса REQ
                if (create_server_cert(req, CERT_RSA, "cert\\ca-cert.pem", "cert\\ca-key.pem", "cert\\server-cert.pem")) // то создаем сам сертификат сервера
                    ok = true;
    }
    else if (ui->radioButton_4->isChecked()) // далее аналогично для других алгоритмов
    {
        if (create_ca_cert(CERT_ECDSA, "cert\\ca-cert.pem", "cert\\ca-key.pem"))
            if ((req = create_server_req(CERT_ECDSA, "cert\\server-req.pem", "cert\\server-key.pem")) != NULL)
                if (create_server_cert(req, CERT_ECDSA, "cert\\ca-cert.pem", "cert\\ca-key.pem", "cert\\server-cert.pem"))
                    ok = true;
    }
    else if (ui->radioButton_6->isChecked())
    {
        if (create_ca_cert(CERT_ED25519, "cert\\ca-cert.pem", "cert\\ca-key.pem"))
            if ((req = create_server_req(CERT_ED25519, "cert\\server-req.pem", "cert\\server-key.pem")) != NULL)
                if (create_server_cert(req, CERT_ED25519, "cert\\ca-cert.pem", "cert\\ca-key.pem", "cert\\server-cert.pem"))
                    ok = true;
    }

    if (ok)
        ui->label->setText("Сертификат успешно создан");
    else
        ui->label->setText("Не удалось создать сертификат сервера!");

    if (req)
        X509_REQ_free(req);
}

void Widget::on_pushButton_4_clicked()
{
    if (bench_dialog)
        return;

    bench_dialog = new Benchmark();
    QObject::connect(bench_dialog, SIGNAL(Closed()), this, SLOT(slotBenchClosed()));
    bench_dialog->show();
}

void Widget::slotBenchClosed()
{
    delete bench_dialog;
    bench_dialog = nullptr;
}

