#ifndef CHATDIALOG_H
#define CHATDIALOG_H

#include <cstdint>
#include <memory>

#include <QWidget>
#include <QtNetwork/QTcpSocket>

#include "crypto.h"

enum class MessageType : int16_t
{
    Text = 1,
    File = 2,
    Tls  = 3
};

struct MessageHeader
{
    int16_t messageType;
    int32_t messageLen;
};

namespace Ui {
class ChatDialog;
}

class KeyPressEater;

class ChatDialog : public QWidget
{
    Q_OBJECT

public:
    explicit ChatDialog(QTcpSocket *tcpSocket, bool isServer, const TlsContext &sslCtx, QWidget *parent = nullptr);
    ~ChatDialog() override;

public slots:
    void slotSendMessage();

private slots:
    void slotReadSocket();

private:
    void flushNetworkBio();
    void printPeerCertificate();

    Ui::ChatDialog *ui;
    KeyPressEater *m_keyPressEater = nullptr;
    QTcpSocket *m_tcpSocket = nullptr;
    QString m_peerIp;
    std::unique_ptr<TlsSession> m_tlsSession;
    bool m_isServer = false;
    bool m_tlsPrintCert = false;
    QByteArray m_recvBuffer;
};

class KeyPressEater : public QObject
{
    Q_OBJECT

public:
    explicit KeyPressEater(QWidget *parent = nullptr);

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

signals:
    void signalSendMessage();
};

#endif // CHATDIALOG_H
