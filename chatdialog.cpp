#include "chatdialog.h"
#include "ui_chatdialog.h"

#include <cstring>

#include <QHostAddress>
#include <QKeyEvent>

ChatDialog::ChatDialog(QTcpSocket *tcpSocket, bool isServer, const TlsContext &sslCtx, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::ChatDialog)
    , m_tcpSocket(tcpSocket)
    , m_tlsSession(std::make_unique<TlsSession>(sslCtx, isServer))
    , m_isServer(isServer)
{
    ui->setupUi(this);

    m_keyPressEater = new KeyPressEater(this);
    connect(m_keyPressEater, &KeyPressEater::signalSendMessage, this, &ChatDialog::slotSendMessage);
    ui->plainTextEdit_2->installEventFilter(m_keyPressEater);

    connect(m_tcpSocket, &QTcpSocket::readyRead, this, &ChatDialog::slotReadSocket);
    m_peerIp = QHostAddress(m_tcpSocket->peerAddress().toIPv4Address()).toString();
    setWindowTitle("Обмен сообщениями TLS 1.3 - " + m_peerIp);

    // для клиента
    if (!m_isServer)
    {
        int err = 0;
        const HandshakeStatus status = m_tlsSession->stepHandshake(&err);
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

    if (m_keyPressEater)
        delete m_keyPressEater;

    if (m_tcpSocket)
        m_tcpSocket->close();
}

void ChatDialog::flushNetworkBio()
{
    if (!m_tlsSession || !m_tcpSocket)
        return;

    const std::vector<char> outgoing = m_tlsSession->takeOutgoingData();
    if (!outgoing.empty())
    {
        m_tcpSocket->write(outgoing.data(), static_cast<qint64>(outgoing.size()));
    }
}

void ChatDialog::printPeerCertificate()
{
    if (m_tlsPrintCert || m_isServer || !m_tlsSession)
        return;

    const PeerCertificateInfo info = m_tlsSession->peerCertificateInfo();
    if (info.valid)
    {
        ui->plainTextEdit->appendPlainText("Сертификат сервера:");
        ui->plainTextEdit->appendPlainText(QString("Кому выдан: ") + QString::fromStdString(info.subject));
        ui->plainTextEdit->appendPlainText(QString("Кем выдан: ") + QString::fromStdString(info.issuer));
        ui->plainTextEdit->appendPlainText(QString("Версия: V") + QString::number(info.version));

        QString pubkeyAlg = QString("Алгоритм открытого ключа: ") + QString::fromStdString(info.publicKeyAlgorithm);
        if (info.showPublicKeyBits)
            pubkeyAlg += QString(" (") + QString::number(info.publicKeyBits) + QString(" бит)");

        ui->plainTextEdit->appendPlainText(pubkeyAlg);
        ui->plainTextEdit->appendPlainText(QString("Алгоритм подписи: ") + QString::fromStdString(info.signatureAlgorithm) + QString("\n"));
    }
    else
    {
        ui->plainTextEdit->appendPlainText("Не удалось получить сертификат сервера!\n\n");
    }

    m_tlsPrintCert = true;
}

void ChatDialog::slotSendMessage()
{
    if (!m_tlsSession || !m_tlsSession->isHandshakeCompleted())
    {
        ui->plainTextEdit->appendPlainText("Соединение TLS еще не установлено!\n\n");
        return;
    }

    const QString message = ui->plainTextEdit_2->toPlainText();
    const QByteArray msgBytes(message.toUtf8());

    ui->plainTextEdit->appendPlainText("Я: " + message + "\n");
    ui->plainTextEdit_2->clear();

    MessageHeader hdr{};
    hdr.messageType = static_cast<int16_t>(MessageType::Text);
    hdr.messageLen = static_cast<int32_t>(msgBytes.length());

    QByteArray packet;
    packet.resize(static_cast<int>(sizeof(MessageHeader)) + msgBytes.length());
    std::memcpy(packet.data(), &hdr, sizeof(MessageHeader));
    std::memcpy(packet.data() + sizeof(MessageHeader), msgBytes.constData(), msgBytes.length());

    const int tlsSend = m_tlsSession->sendApplicationData(packet.constData(), packet.size());
    if (tlsSend <= 0)
    {
        ui->plainTextEdit->appendPlainText("Ошибка при отправке TLS сообщения!\n\n");
        return;
    }

    flushNetworkBio();
}

void ChatDialog::slotReadSocket()
{
    if (!m_tlsSession || !m_tcpSocket)
        return;

    const QByteArray incoming = m_tcpSocket->readAll();
    if (incoming.isEmpty())
        return;

    m_tlsSession->feedIncomingData(incoming.constData(), incoming.size());

    // если мы на этапе хендшейка
    if (!m_tlsSession->isHandshakeCompleted())
    {
        int err = 0;
        const HandshakeStatus status = m_tlsSession->stepHandshake(&err);
        flushNetworkBio();

        if (status == HandshakeStatus::Failed)
        {
            const QString peerRole = m_isServer ? "клиентом" : "сервером";
            ui->plainTextEdit->appendPlainText("Не удалось установить соединение с " + peerRole + ": код ошибки " + QString::number(err) + "!\n\n");
            return;
        }
        else if (status == HandshakeStatus::Completed)
        {
            if (m_isServer)
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
    const int tlsRecv = m_tlsSession->receiveApplicationData(buf, sizeof(buf));
    flushNetworkBio();

    if (tlsRecv == 0)
        return;

    if (tlsRecv < 0)
    {
        ui->plainTextEdit->appendPlainText("Ошибка при получении TLS сообщения: код ошибки " + QString::number(-tlsRecv) + "!\n\n");
        return;
    }

    m_recvBuffer.append(buf, tlsRecv);

    while (m_recvBuffer.size() >= static_cast<int>(sizeof(MessageHeader)))
    {
        MessageHeader hdr{};
        std::memcpy(&hdr, m_recvBuffer.constData(), sizeof(MessageHeader));

        if (hdr.messageLen < 0)
        {
            m_recvBuffer.clear();
            break;
        }

        const int frameSize = static_cast<int>(sizeof(MessageHeader)) + hdr.messageLen;
        if (m_recvBuffer.size() < frameSize)
            break;

        const QByteArray payload = m_recvBuffer.mid(sizeof(MessageHeader), hdr.messageLen);
        m_recvBuffer.remove(0, frameSize);

        switch (static_cast<MessageType>(hdr.messageType))
        {
        case MessageType::Text:
        {
            const QString message = QString::fromUtf8(payload);
            ui->plainTextEdit->appendPlainText(m_peerIp + ": " + message + "\n");
            break;
        }
        default:
            break;
        }
    }
}

KeyPressEater::KeyPressEater(QWidget *parent)
    : QObject(parent)
{
}

bool KeyPressEater::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress)
    {
        const QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);

        if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter)
        {
            emit signalSendMessage();
            return true;
        }
    }

    return QObject::eventFilter(obj, event);
}
