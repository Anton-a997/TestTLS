#ifndef CHATDIALOG_H
#define CHATDIALOG_H

#include <memory>

#include <QWidget>
#include <QFileDialog>
#include <QMessageBox>
#include <QtNetwork/QTcpSocket>
#include <QtNetwork/QTcpServer>

#include "crypto.h"

#define MESSAGE_TEXT 1
#define MESSAGE_FILE 2
#define MESSAGE_TLS  3

typedef struct _MESSAGE_HEADER
{
    short message_type;
    int message_len;
} MESSAGE_HEADER;

namespace Ui {
class ChatDialog;
}

class KeyPressEater;

class ChatDialog : public QWidget
{
    Q_OBJECT

public:
    explicit ChatDialog(QTcpSocket *tcp_socket, bool is_server, const TlsContext &ssl_ctx, QWidget *parent = nullptr);
    ~ChatDialog() override;

private:
    Ui::ChatDialog *ui;

    KeyPressEater *keyPressEater = nullptr;

    QTcpSocket *tcp_socket = nullptr;
    QString peer_ip;

    std::unique_ptr<TlsSession> tls_session;

    bool is_server;
    bool tls_print_cert = false;

    QByteArray recv_buffer;

    void flushNetworkBio();
    void printPeerCertificate();

public slots:
    void slotSendMessage();

private slots:
    void slotReadSocket();
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
