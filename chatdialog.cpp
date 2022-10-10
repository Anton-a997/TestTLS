#include "chatdialog.h"
#include "ui_chatdialog.h"

#include <QDebug>

ChatDialog::ChatDialog(QTcpSocket *tcp_socket, bool is_server, SSL_CTX *ssl_ctx, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ChatDialog)
{
    ui->setupUi(this);

    this->is_server = is_server;

    // создание объекта SSL - используется в течение одной TLS сессии
    ssl = SSL_new(ssl_ctx);
    // BIO - буферы, в которые будут писать и читать функции OpenSSL для обмена по TLS
    BIO_new_bio_pair(&internal_bio, 0, &network_bio, 0);
    // устанавливаем созданные буферы для TLS сессии
    SSL_set_bio(ssl, internal_bio, internal_bio);

    // настройка виджета
    keyPressEater = new KeyPressEater(this);
    connect(keyPressEater, SIGNAL(signalSendMessage()), this, SLOT(slotSendMessage()));
    ui->plainTextEdit_2->installEventFilter(keyPressEater);

    this->tcp_socket = tcp_socket;
    connect(tcp_socket, SIGNAL(readyRead()), this, SLOT(slotReadSocket()));
    qint32 ip = tcp_socket->peerAddress().toIPv4Address();
    unsigned char *c_ip = (unsigned char*)&ip;
    peer_ip = QString::number(c_ip[3]) + "." + QString::number(c_ip[2]) + "." + QString::number(c_ip[1]) + "." + QString::number(c_ip[0]);
    setWindowTitle("Обмен сообщениями TLS 1.3 - " + peer_ip);
    // ///

    // для клиента
    if (!is_server)
    {
        char buf[4096];
        int status = 0;
        status = SSL_connect(ssl); // клиент инициирует подключение к серверу

        // чтение данных клиента TLS из BIO и отправка их через обычный TCP сокет
        int bread = BIO_read(network_bio, buf, sizeof(buf));
        tcp_socket->write(buf, bread);

        // проверка статуса операции
        if (status <= 0)
        {
            int err = SSL_get_error(ssl, status);

            // эта ошибка значит, что клиенту требуются данные от сервера - установка соединения продолжается
            if (err != SSL_ERROR_WANT_READ)
                // другая ошибка критична
                ui->plainTextEdit->appendPlainText("Не удалось установить соединение с сервером: код ошибки " + QString::number(err) +"!\n\n");
        }
        else
        {
            tls_connect = true;
        }
    }
}

ChatDialog::~ChatDialog()
{
    delete ui;

    if (keyPressEater)
        delete keyPressEater;

    if (tcp_socket)
        tcp_socket->close();

    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
}

void ChatDialog::slotSendMessage()
{
    // открытое сообщение сохраняется в массив байт
    QString message = ui->plainTextEdit_2->toPlainText();
    QByteArray msg_bytes(message.toUtf8());

    ui->plainTextEdit->appendPlainText("Я: " + message + "\n");
    ui->plainTextEdit_2->clear();

    // заголовок открытого сообщения, чтоб знать длину
    MESSAGE_HEADER hdr;
    hdr.message_type = MESSAGE_TEXT;
    hdr.message_len = msg_bytes.length();

    // копирование заголовка и сообщения в буфер
    char buf[8192];
    memcpy(buf, &hdr, sizeof(MESSAGE_HEADER));
    memcpy(buf + sizeof(MESSAGE_HEADER), msg_bytes.data(), msg_bytes.length());

    // отправка подготовленных данных через TLS - они попадают в буфер BIO
    int tls_send = tls_send_packet(ssl, buf, static_cast<int>(sizeof(MESSAGE_HEADER) + msg_bytes.length()));

    // ошибка
    if (tls_send <= 0)
    {
        ui->plainTextEdit->appendPlainText("Ошибка при отправке TLS сообщения!\n\n");
        return;
    }

    // из BIO данные берутся в зашифрованном виде и отправляются через TCP сокет
    int bread = BIO_read(network_bio, buf, sizeof(buf));
    tcp_socket->write(buf, bread);
}

void ChatDialog::slotReadSocket()
{
    char buf[16384];

    // на TCP сокет пришел зашифрованный пакет
    int brecv = tcp_socket->read(buf, 16384);
    // получаем его и отправляем в буфер BIO
    BIO_write(network_bio, buf, brecv);

    // если мы на этапе хендшейка
    if (!tls_connect)
    {
        int bread = 0;

        // для сервера
        if (is_server)
        {
            int status = 0;
            status = SSL_accept(ssl); // сервер получил пакет от клиента и продолжает хендшейк

            // чтение данных от сервера TLS из BIO
            bread = BIO_read(network_bio, buf, sizeof(buf));

            // проверка статуса операции
            if (status <= 0)
            {
                int err = SSL_get_error(ssl, status);

                // эта ошибка значит, что серверу требуются данные от клиента - установка соединения продолжается
                if (err != SSL_ERROR_WANT_READ)
                    // другая ошибка критична
                    ui->plainTextEdit->appendPlainText("Не удалось установить соединение с сервером: код ошибки " + QString::number(err) +"!\n\n");
            }
            else
            {
                // status == 1 - хендшейк установлен
                tls_connect = true;
                ui->plainTextEdit->appendPlainText("Установлено TLS соединение с клиентом!\n");
            }
        }

        // для клиента
        if (!is_server)
        {
            int status = 0;
            status = SSL_connect(ssl); // клиент получил пакет от сервера и продолжает хендшейк

            // чтение данных от клиента TLS из BIO
            bread = BIO_read(network_bio, buf, sizeof(buf));

            // проверка статуса операции
            if (status <= 0)
            {
                int err = SSL_get_error(ssl, status);

                // эта ошибка значит, что клиенту требуются данные от сервера - установка соединения продолжается
                if (err != SSL_ERROR_WANT_READ)
                    // другая ошибка критична
                    ui->plainTextEdit->appendPlainText("Не удалось установить соединение с сервером: код ошибки " + QString::number(err) +"!\n\n");
            }
            else
            {
                // status == 1 - хендшейк установлен
                tls_connect = true;
                ui->plainTextEdit->appendPlainText("Установлено TLS соединение с сервером!\n");
            }
        }

        // отправка ответа клиента через TCP сокет
        tcp_socket->write(buf, bread);

        return;
    }

    // если мы на этапе обмена сообщениями, получаем расшифрованный пакет TLS из BIO
    int tls_recv = tls_recv_packet(ssl, buf, sizeof(buf));

    // пустой пакет
    if (tls_recv == 0)
        return;

    // первый пакет от сервера после хендшейка
    if (tls_recv < 0)
    {
        // клиент выводит сертификат
        if (!tls_print_cert && !is_server)
        {
            X509 *cert = SSL_get_peer_certificate(ssl);

            if (cert != nullptr)
            {
                ui->plainTextEdit->appendPlainText("Сертификат сервера:");

                char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                ui->plainTextEdit->appendPlainText(QString("Кому выдан: ") + QString(line));
                delete line;

                line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
                ui->plainTextEdit->appendPlainText(QString("Кем видан: ") + QString(line));
                delete line;

                ui->plainTextEdit->appendPlainText(QString("Версия: V") + QString::number(X509_get_version(cert) + 1));

                EVP_PKEY* pubkey = X509_get_pubkey(cert);
                QString pubkey_alg = QString("Алгоритм открытого ключа: ") + QString(EVP_PKEY_get_type_name(pubkey));

                if (EVP_PKEY_get_type_name(pubkey)[0] != '1')
                    pubkey_alg += QString(" (") + QString::number(EVP_PKEY_bits(pubkey)) + QString(" бит)");

                ui->plainTextEdit->appendPlainText(pubkey_alg);
                ui->plainTextEdit->appendPlainText(QString("Алгоритм подписи: ") + QString(OBJ_nid2sn(X509_get_signature_nid(cert))) + QString("\n"));

                EVP_PKEY_free(pubkey);
                X509_free(cert);
            }
            else
            {
                ui->plainTextEdit->appendPlainText("Не удалось получить сертификат сервера!\n\n");
            }

            tls_print_cert = true;
        }
        else
            ui->plainTextEdit->appendPlainText("Ошибка при получении TLS сообщения: код ошибки " + QString::number(-tls_recv) + "!\n\n");

        return;
    }

    // обмен сообщениями
    char* rd_buf = buf;

    static QByteArray data; // массив полученных байт открытого сообщения
    static MESSAGE_HEADER hdr; // заголовок открытого сообщения
    static int data_read; // сколько получено байт

    hdr = *(MESSAGE_HEADER*)rd_buf; // чтение заголовка сообщения
    rd_buf += sizeof(MESSAGE_HEADER);

    data_read = 0;
    data.clear();

    // если получено меньше, чем указано в заголовке сообщения
    if (data_read < hdr.message_len)
    {
        // запоминием полученную часть
        QByteArray part = QByteArray(rd_buf, hdr.message_len - data_read);
        data_read += part.length();
        data += part;
    }

    // если получено меньше, чем указано в заголовке сообщения, выходим из функции - потом получим ещё
    if (data_read < hdr.message_len)
        return;

    // если сообщение готово
    QString message;

    // Выводим в виджет
    switch (hdr.message_type)
    {
    case MESSAGE_TEXT:
        message = QString(data);
        ui->plainTextEdit->appendPlainText(peer_ip + ": " + message + "\n");
        break;

    default:
        break;
    }
}

KeyPressEater::KeyPressEater(QWidget *parent):
    QObject(parent)
{
}

bool KeyPressEater::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);

        if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Return + 1)
        {
            emit signalSendMessage();
            return true;
        }
    }

    return QObject::eventFilter(obj, event);
}
