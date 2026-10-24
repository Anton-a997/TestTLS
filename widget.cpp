#include "widget.h"
#include "ui_widget.h"

#include <QDir>
#include <QHostAddress>

namespace {
constexpr quint16 kDefaultTlsPort = 13337;
} // namespace

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);

    QDir().mkpath("cert");

    TlsContext::initializeOpenSsl();
}

Widget::~Widget()
{
    if (m_tcpServer)
    {
        m_tcpServer->close();
        delete m_tcpServer;
    }

    delete ui;
}

void Widget::on_pushButton_clicked()
{
    connectToIp();
}

void Widget::slotClientConnected()
{
    QTcpSocket *tcpSocket = m_tcpServer->nextPendingConnection();
    const QString peerIp = QHostAddress(tcpSocket->peerAddress().toIPv4Address()).toString();
    ui->label->setText(QString("Входящее соединение от клиента ") + peerIp);

    ChatDialog *chatDialog = new ChatDialog(tcpSocket, true, *m_sslServerCtx);
    chatDialog->setAttribute(Qt::WA_DeleteOnClose);
    chatDialog->show();
}

bool Widget::startServer()
{
    const char *algString = "";

    // выбор алгоритма шифрования на сессию
    if (ui->radioButton->isChecked())
        algString = "TLS_AES_256_GCM_SHA384";
    else if (ui->radioButton_2->isChecked())
        algString = "TLS_CHACHA20_POLY1305_SHA256";
    else if (ui->radioButton_3->isChecked())
        algString = "TLS_AES_128_GCM_SHA256";

    // создание контекста SSL для сервера
    m_sslServerCtx = TlsContext::createServerContext(algString);
    if (!m_sslServerCtx)
    {
        ui->label->setText("Не удалось создать контекст SSL");
        return false;
    }

    // загрузка сертификатов сервера
    if (!m_sslServerCtx->loadCertificateAndKey("cert/server-cert.pem", "cert/server-key.pem"))
    {
        m_sslServerCtx.reset();
        ui->label->setText("Не удалось загрузить сертификат и ключ сервера!");
        return false;
    }

    // запуск сервера
    m_tcpServer = new QTcpServer(this);
    connect(m_tcpServer, &QTcpServer::newConnection, this, &Widget::slotClientConnected);

    if (!m_tcpServer->listen(QHostAddress::Any, kDefaultTlsPort))
    {
        m_sslServerCtx.reset();

        ui->label->setText(QObject::tr("Не удалось запустить сервер: %1.").arg(m_tcpServer->errorString()));
        delete m_tcpServer;
        m_tcpServer = nullptr;
        return false;
    }

    ui->label->setText("Ожидание подключения клиента...");
    return true;
}

void Widget::connectToIp()
{
    QString strIp = ui->lineEdit->text();
    strIp.remove(' ');

    QTcpSocket *tcpSocket = new QTcpSocket();
    tcpSocket->connectToHost(strIp, kDefaultTlsPort);

    if (!tcpSocket->waitForConnected())
    {
        delete tcpSocket;
        QMessageBox::critical(this, "Ошибка", "Не удалось установить соединение с сервером!");
        return;
    }

    ui->lineEdit->clear();
    m_sslClientCtx = TlsContext::createClientContext(true);

    if (!m_sslClientCtx)
    {
        tcpSocket->close();
        delete tcpSocket;
        QMessageBox::critical(this, "Ошибка", "Не удалось создать контекст SSL!");
        return;
    }

    ChatDialog *chatDialog = new ChatDialog(tcpSocket, false, *m_sslClientCtx);
    chatDialog->setAttribute(Qt::WA_DeleteOnClose);
    chatDialog->show();
}

void Widget::on_pushButton_2_clicked()
{
    if (startServer())
        ui->pushButton_2->setEnabled(false);
}

void Widget::on_pushButton_3_clicked()
{
    // генерация сертификатов
    CertAlgorithm alg = CertAlgorithm::Rsa;

    if (ui->radioButton_5->isChecked())
        alg = CertAlgorithm::Rsa;
    else if (ui->radioButton_4->isChecked())
        alg = CertAlgorithm::Ecdsa;
    else if (ui->radioButton_6->isChecked())
        alg = CertAlgorithm::Ed25519;

    const bool ok = CertificateGenerator::generateServerCertificateChain(
        alg,
        "cert/ca-cert.pem",
        "cert/ca-key.pem",
        "cert/server-req.pem",
        "cert/server-key.pem",
        "cert/server-cert.pem"
    );

    if (ok)
        ui->label->setText("Сертификат успешно создан");
    else
        ui->label->setText("Не удалось создать сертификат сервера!");
}

void Widget::on_pushButton_4_clicked()
{
    if (m_benchDialog)
        return;

    m_benchDialog = new Benchmark();
    connect(m_benchDialog, &Benchmark::Closed, this, &Widget::slotBenchClosed);
    m_benchDialog->show();
}

void Widget::slotBenchClosed()
{
    delete m_benchDialog;
    m_benchDialog = nullptr;
}
