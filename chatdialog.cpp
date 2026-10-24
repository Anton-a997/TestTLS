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
        int status = SSL_connect(ssl); // клиент инициирует подключение к серверу

        // чтение данных клиента TLS из BIO и отправка их через обычный TCP сокет
        flushNetworkBio();

        // проверка статуса операции
        if (status <= 0)
        {
            int err = SSL_get_error(ssl, status);

            // эта ошибка значит, что клиенту требуются данные от сервера - установка соединения продолжается
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                // другая ошибка критична
                ui->plainTextEdit->appendPlainText("Не удалось установить соединение с сервером: код ошибки " + QString::number(err) +"!\n\n");
        }
        else
        {
            tls_connect = true;
            printPeerCertificate();
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

    if (network_bio)
        BIO_free(network_bio);
}

void ChatDialog::flushNetworkBio()
{
    if (!network_bio || !tcp_socket)
        return;

    char buf[4096];
    int bread = 0;

    while ((bread = BIO_read(network_bio, buf, sizeof(buf))) > 0)
    {
        tcp_socket->write(buf, bread);
    }
}

void ChatDialog::printPeerCertificate()
{
    if (tls_print_cert || is_server || !ssl)
        return;

    X509 *cert = SSL_get1_peer_certificate(ssl);

    if (cert != nullptr)
    {
        ui->plainTextEdit->appendPlainText("Сертификат сервера:");

        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        if (line)
        {
            ui->plainTextEdit->appendPlainText(QString("Кому выдан: ") + QString(line));
            OPENSSL_free(line);
        }

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        if (line)
        {
            ui->plainTextEdit->appendPlainText(QString("Кем выдан: ") + QString(line));
            OPENSSL_free(line);
        }

        ui->plainTextEdit->appendPlainText(QString("Версия: V") + QString::number(X509_get_version(cert) + 1));

        EVP_PKEY* pubkey = X509_get_pubkey(cert);
        if (pubkey)
        {
            const char *type_name = EVP_PKEY_get_type_name(pubkey);
            QString pubkey_alg = QString("Алгоритм открытого ключа: ") + QString(type_name ? type_name : "");

            if (EVP_PKEY_get_base_id(pubkey) != EVP_PKEY_ED25519)
                pubkey_alg += QString(" (") + QString::number(EVP_PKEY_bits(pubkey)) + QString(" бит)");

            ui->plainTextEdit->appendPlainText(pubkey_alg);
            EVP_PKEY_free(pubkey);
        }

        ui->plainTextEdit->appendPlainText(QString("Алгоритм подписи: ") + QString(OBJ_nid2sn(X509_get_signature_nid(cert))) + QString("\n"));

        X509_free(cert);
    }
    else
    {
        ui->plainTextEdit->appendPlainText("Не удалось получить сертификат сервера!\n\n");
    }

    tls_print_cert = true;
}

void ChatDialog::slotSendMessage()
{
    if (!tls_connect)
    {
        ui->plainTextEdit->appendPlainText("Соединение TLS еще не установлено!\n\n");
        return;
    }

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
    QByteArray packet;
    packet.resize(static_cast<int>(sizeof(MESSAGE_HEADER)) + msg_bytes.length());
    memcpy(packet.data(), &hdr, sizeof(MESSAGE_HEADER));
    memcpy(packet.data() + sizeof(MESSAGE_HEADER), msg_bytes.constData(), msg_bytes.length());

    // отправка подготовленных данных через TLS - они попадают в буфер BIO
    int tls_send = tls_send_packet(ssl, packet.constData(), packet.size());

    // ошибка
    if (tls_send <= 0)
    {
        ui->plainTextEdit->appendPlainText("Ошибка при отправке TLS сообщения!\n\n");
        return;
    }

    // из BIO данные берутся в зашифрованном виде и отправляются через TCP сокет
    flushNetworkBio();
}

void ChatDialog::slotReadSocket()
{
    // на TCP сокет пришел зашифрованный пакет
    QByteArray incoming = tcp_socket->readAll();
    if (incoming.isEmpty())
        return;

    // получаем его и отправляем в буфер BIO
    BIO_write(network_bio, incoming.constData(), incoming.size());

    // если мы на этапе хендшейка
    if (!tls_connect)
    {
        // для сервера
        if (is_server)
        {
            int status = SSL_accept(ssl); // сервер получил пакет от клиента и продолжает хендшейк

            // отправка данных от сервера TLS из BIO через TCP сокет
            flushNetworkBio();

            // проверка статуса операции
            if (status <= 0)
            {
                int err = SSL_get_error(ssl, status);

                // эта ошибка значит, что серверу требуются данные от клиента - установка соединения продолжается
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                    // другая ошибка критична
                    ui->plainTextEdit->appendPlainText("Не удалось установить соединение с клиентом: код ошибки " + QString::number(err) +"!\n\n");
                return;
            }
            else
            {
                // status == 1 - хендшейк установлен
                tls_connect = true;
                ui->plainTextEdit->appendPlainText("Установлено TLS соединение с клиентом!\n");
            }
        }
        else
        {
            // для клиента
            int status = SSL_connect(ssl); // клиент получил пакет от сервера и продолжает хендшейк

            // отправка ответа клиента из BIO через TCP сокет
            flushNetworkBio();

            // проверка статуса операции
            if (status <= 0)
            {
                int err = SSL_get_error(ssl, status);

                // эта ошибка значит, что клиенту требуются данные от сервера - установка соединения продолжается
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                    // другая ошибка критична
                    ui->plainTextEdit->appendPlainText("Не удалось установить соединение с сервером: код ошибки " + QString::number(err) +"!\n\n");
                return;
            }
            else
            {
                // status == 1 - хендшейк установлен
                tls_connect = true;
                ui->plainTextEdit->appendPlainText("Установлено TLS соединение с сервером!\n");
                printPeerCertificate();
            }
        }
    }

    // если мы на этапе обмена сообщениями, получаем расшифрованный пакет TLS из BIO
    char buf[16384];
    int tls_recv = tls_recv_packet(ssl, buf, sizeof(buf));
    flushNetworkBio();

    // пустой пакет (например, обработан пост-хендшейк пакет NewSessionTicket)
    if (tls_recv == 0)
        return;

    if (tls_recv < 0)
    {
        ui->plainTextEdit->appendPlainText("Ошибка при получении TLS сообщения: код ошибки " + QString::number(-tls_recv) + "!\n\n");
        return;
    }

    // накопление полученных байт открытого сообщения и разбор кадров
    recv_buffer.append(buf, tls_recv);

    while (recv_buffer.size() >= static_cast<int>(sizeof(MESSAGE_HEADER)))
    {
        MESSAGE_HEADER hdr;
        memcpy(&hdr, recv_buffer.constData(), sizeof(MESSAGE_HEADER));

        if (hdr.message_len < 0)
        {
            recv_buffer.clear();
            break;
        }

        int frame_size = static_cast<int>(sizeof(MESSAGE_HEADER)) + hdr.message_len;
        if (recv_buffer.size() < frame_size)
            break;

        QByteArray payload = recv_buffer.mid(sizeof(MESSAGE_HEADER), hdr.message_len);
        recv_buffer.remove(0, frame_size);

        switch (hdr.message_type)
        {
        case MESSAGE_TEXT:
        {
            QString message = QString::fromUtf8(payload);
            ui->plainTextEdit->appendPlainText(peer_ip + ": " + message + "\n");
            break;
        }
        default:
            break;
        }
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

        if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter)
        {
            emit signalSendMessage();
            return true;
        }
    }

    return QObject::eventFilter(obj, event);
}
