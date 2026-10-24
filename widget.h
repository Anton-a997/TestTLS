#ifndef WIDGET_H
#define WIDGET_H

#include <memory>

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
    explicit Widget(QWidget *parent = nullptr);
    ~Widget() override;

private slots:
    void on_pushButton_clicked();
    void slotClientConnected();
    void on_pushButton_2_clicked();
    void on_pushButton_3_clicked();
    void on_pushButton_4_clicked();
    void slotBenchClosed();

private:
    bool startServer();
    void connectToIp();

    Ui::Widget *ui;
    Benchmark *m_benchDialog = nullptr;
    QTcpServer *m_tcpServer = nullptr;
    std::unique_ptr<TlsContext> m_sslServerCtx;
    std::unique_ptr<TlsContext> m_sslClientCtx;
};

#endif // WIDGET_H
