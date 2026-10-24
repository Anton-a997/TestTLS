#include "chatdialog.h"
#include "ui_chatdialog.h"

#include <QKeyEvent>
#include <cstring>

ChatDialog::ChatDialog(QTcpSocket *tcp_socket, bool is_server, const TlsContext &ssl_ctx, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ChatDialog),
    tls_session(std::make_unique<TlsSession>(ssl_ctx, is_server)),
    is_server(is_server)
{
    ui->setupUi(this);

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

    // для клиента
    if (!is_server)
    {
        int err = 0;
        HandshakeStatus status = tls_session->stepHandshake(&err);
        flushNetworkBio();

        if (status == HandshakeStatus::Failed)
        {
            ui->plainTextEdit->appendPlainText("Не удалось установить соединение с сервером: код ошибки " + QString::number(err) + "!\n\n");
        }
        else if (status == HandshakeStatus::Completed)
        {
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
}

void ChatDialog::flushNetworkBio()
{
    if (!tls_session || !tcp_socket)
        return;

    std::vector<char> outgoing = tls_session->takeOutgoingData();
    if (!outgoing.empty())
    {
        tcp_socket->write(outgoing.data(), static_cast<qint64>(outgoing.size()));
    }
}

void ChatDialog::printPeerCertificate()
{
    if (tls_print_cert || is_server || !tls_session)
        return;

    PeerCertificateInfo info = tls_session->peerCertificateInfo();
    if (info.valid)
    {
        ui->plainTextEdit->appendPlainText("Сертификат сервера:");
        ui->plainTextEdit->appendPlainText(QString("Кому выдан: ") + QString::fromStdString(info.subject));
        ui->plainTextEdit->appendPlainText(QString("Кем выдан: ") + QString::fromStdString(info.issuer));
        ui->plainTextEdit->appendPlainText(QString("Версия: V") + QString::number(info.version));

        QString pubkey_alg = QString("Алгоритм открытого ключа: ") + QString::fromStdString(info.publicKeyAlgorithm);
        if (info.showPublicKeyBits)
            pubkey_alg += QString(" (") + QString::number(info.publicKeyBits) + QString(" бит)");

        ui->plainTextEdit->appendPlainText(pubkey_alg);
        ui->plainTextEdit->appendPlainText(QString("Алгоритм подписи: ") + QString::fromStdString(info.signatureAlgorithm) + QString("\n"));
    }
    else
    {
        ui->plainTextEdit->appendPlainText("Не удалось получить сертификат сервера!\n\n");
    }

    tls_print_cert = true;
}

void ChatDialog::slotSendMessage()
{
    if (!tls_session || !tls_session->isHandshakeCompleted())
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
    std::memcpy(packet.data(), &hdr, sizeof(MESSAGE_HEADER));
    std::memcpy(packet.data() + sizeof(MESSAGE_HEADER), msg_bytes.constData(), msg_bytes.length());

    // отправка подготовленных данных через TLS
    int tls_send = tls_session->sendApplicationData(packet.constData(), packet.size());
    if (tls_send <= 0)
    {
        ui->plainTextEdit->appendPlainText("Ошибка при отправке TLS сообщения!\n\n");
        return;
    }

    flushNetworkBio();
}

void ChatDialog::slotReadSocket()
{
    if (!tls_session || !tcp_socket)
        return;

    QByteArray incoming = tcp_socket->readAll();
    if (incoming.isEmpty())
        return;

    tls_session->feedIncomingData(incoming.constData(), incoming.size());

    // если мы на этапе хендшейка
    if (!tls_session->isHandshakeCompleted())
    {
        int err = 0;
        HandshakeStatus status = tls_session->stepHandshake(&err);
        flushNetworkBio();

        if (status == HandshakeStatus::Failed)
        {
            QString peer_role = is_server ? "клиентом" : "сервером";
            ui->plainTextEdit->appendPlainText("Не удалось установить соединение с " + peer_role + ": код ошибки " + QString::number(err) + "!\n\n");
            return;
        }
        else if (status == HandshakeStatus::Completed)
        {
            if (is_server)
            {
                ui->plainTextEdit->appendPlainText("Установлено TLS соединение с клиентом!\n");
            }
            else
            {
                ui->plainTextEdit->appendPlainText("Установлено TLS соединение с сервером!\n");
                printPeerCertificate();
            }
        }
        else
        {
            return;
        }
    }

    // если мы на этапе обмена сообщениями, получаем расшифрованный пакет TLS
    char buf[16384];
    int tls_recv = tls_session->receiveApplicationData(buf, sizeof(buf));
    flushNetworkBio();

    if (tls_recv == 0)
        return;

    if (tls_recv < 0)
    {
        ui->plainTextEdit->appendPlainText("Ошибка при получении TLS сообщения: код ошибки " + QString::number(-tls_recv) + "!\n\n");
        return;
    }

    recv_buffer.append(buf, tls_recv);

    while (recv_buffer.size() >= static_cast<int>(sizeof(MESSAGE_HEADER)))
    {
        MESSAGE_HEADER hdr;
        std::memcpy(&hdr, recv_buffer.constData(), sizeof(MESSAGE_HEADER));

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
