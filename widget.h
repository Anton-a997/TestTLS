#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>

#include <QMessageBox>
#include <QtNetwork/QTcpSocket>
#include <QtNetwork/QTcpServer>

#include "chatdialog.h"
#include "benchmark.h"
#include "crypto.h"

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

private slots:
    void on_pushButton_clicked();

    void slotClientConnected();

    void on_pushButton_2_clicked();

    void on_pushButton_3_clicked();

    void on_pushButton_4_clicked();

    void slotBenchClosed();

private:
    Ui::Widget *ui;

    Benchmark *bench_dialog = nullptr;

    QTcpServer *tcp_server = nullptr;

    SSL_CTX *ssl_server_ctx = 0;
    SSL_CTX *ssl_client_ctx = 0;

    bool StartServer(); // запуск сервера
    void ConnectToIP(); // подключение клиента
};

#endif // WIDGET_H
