#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <QWidget>
#include <QCloseEvent>
#include <QMessageBox>
#include <QList>

#include "crypto.h"

namespace Ui {
class Benchmark;
}

class Benchmark : public QWidget
{
    Q_OBJECT

public:
    explicit Benchmark(QWidget *parent = nullptr);
    ~Benchmark() override;

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    Ui::Benchmark *ui;

    void ResetTable();
    void StartBench();

    bool TLS_send_message(TlsSession &ssl_client, TlsSession &ssl_server);

    QList<long long> GetStatistics(QList<long long> measurements);

    long CERT_SIGN_ATTEMPTS = 1000;
    long HANDSHAKE_ATTEMPTS = 1000;
    long MESSAGES_TO_SEND = 100000;

#define MESSAGE_EXCHANGE_SESSIONS 50
#define MESSAGE_SIZE 256

signals:
    void Closed();
private slots:
    void on_pushButton_clicked();

    void on_spinBox_valueChanged(int arg1);
    void on_spinBox_2_valueChanged(int arg1);
    void on_spinBox_3_valueChanged(int arg1);
};

#endif // BENCHMARK_H
