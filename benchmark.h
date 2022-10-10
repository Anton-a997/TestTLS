#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <QWidget>
#include <QtAlgorithms>
#include <QCloseEvent>
#include <QMessageBox>
#include <QList>

#include "crypto.h"
#include "crypto_bench.h"

namespace Ui {
class Benchmark;
}

class Benchmark : public QWidget
{
    Q_OBJECT

public:
    explicit Benchmark(QWidget *parent = nullptr);
    ~Benchmark();

protected:
     void closeEvent(QCloseEvent *event);

private:
    Ui::Benchmark *ui;

    void ResetTable();
    void StartBench();

    bool TLS_Handshake(SSL* ssl_client, SSL* ssl_server, long long &time_handshake);
    bool TLS_send_message(SSL* ssl_client, SSL* ssl_server);

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
