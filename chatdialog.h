#ifndef CHATDIALOG_H
#define CHATDIALOG_H

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
    explicit ChatDialog(QTcpSocket *tcp_socket, bool is_server, SSL_CTX *ssl_ctx, QWidget *parent = 0);
    ~ChatDialog();

private:
    Ui::ChatDialog *ui;

    KeyPressEater *keyPressEater = 0;

    QTcpSocket *tcp_socket = 0;
    QString peer_ip;

    SSL *ssl = 0; // объект SSL - используется в течение одной TLS сессии
    BIO *internal_bio, *network_bio; // буферы для чтения и записи TLS сообщений

    bool is_server;
    bool tls_connect = false;
    bool tls_print_cert = false;

    int pub_alg = 0;

public slots:
    void slotSendMessage();

private slots:
    void slotReadSocket();
};

class KeyPressEater : public QObject
{
    Q_OBJECT

public:
    explicit KeyPressEater(QWidget *parent = 0);

protected:
    bool eventFilter(QObject *obj, QEvent *event);

signals:
    void signalSendMessage();
};

#endif // CHATDIALOG_H
