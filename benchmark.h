#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <QWidget>
#include <QCloseEvent>
#include <QMessageBox>
#include <QList>
#include <QThread>

#include "crypto.h"

namespace Ui {
class Benchmark;
}

struct BenchmarkConfig
{
    CertAlgorithm certAlgorithm = CertAlgorithm::Rsa;
    std::string cipherSuite;
    long certSignAttempts = 1000;
    long handshakeAttempts = 1000;
    long messagesToSend = 100000;
};

struct BenchmarkResult
{
    int certSignSucceeded = 0;
    int certVerifySucceeded = 0;
    int handshakeSucceeded = 0;
    long messagesToSend = 0;
    QList<long long> certSignStats;
    QList<long long> certVerifyStats;
    QList<long long> handshakeStats;
    QList<long long> msgExchangeStats;
};

Q_DECLARE_METATYPE(BenchmarkResult)

class BenchmarkWorker : public QObject
{
    Q_OBJECT

public:
    static constexpr int kMessageExchangeSessions = 50;
    static constexpr int kMessageSize = 256;

    explicit BenchmarkWorker(const BenchmarkConfig &config, QObject *parent = nullptr);

public slots:
    void process();

signals:
    void progressUpdated(int percent);
    void finished(const BenchmarkResult &result);
    void errorOccurred(const QString &message);

private:
    static bool sendAndReceiveMessage(TlsSession &sslClient, TlsSession &sslServer);
    static QList<long long> computeStatistics(QList<long long> measurements);

    BenchmarkConfig m_config;
};

class Benchmark : public QWidget
{
    Q_OBJECT

public:
    explicit Benchmark(QWidget *parent = nullptr);
    ~Benchmark() override;

protected:
    void closeEvent(QCloseEvent *event) override;

signals:
    void Closed();

private slots:
    void on_pushButton_clicked();
    void on_spinBox_valueChanged(int arg1);
    void on_spinBox_2_valueChanged(int arg1);
    void on_spinBox_3_valueChanged(int arg1);

    void onBenchmarkProgress(int percent);
    void onBenchmarkFinished(const BenchmarkResult &result);
    void onBenchmarkError(const QString &message);

private:
    void resetTable();
    void startBench();
    void stopWorkerThread();
    void setControlsEnabled(bool enabled);

    Ui::Benchmark *ui;
    QThread *m_workerThread = nullptr;
    long m_certSignAttempts = 1000;
    long m_handshakeAttempts = 1000;
    long m_messagesToSend = 100000;
};

#endif // BENCHMARK_H
