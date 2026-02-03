#pragma once

#include <QtWidgets/QMainWindow>
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
#include "ui_MusicUSBEncrypt.h"
#else
#include "ui_MusicUSBEncrypt_Qt5.9.9.h"
#endif
#include <Logger.h>

class MusicUSBEncrypt : public QMainWindow
{
    Q_OBJECT
    static std::vector<LoggerSinkPtr> loggerSinks;
    static Logger logger;

public:
    MusicUSBEncrypt(QWidget *parent = nullptr);
    ~MusicUSBEncrypt();

private:
    Ui::MusicUSBEncryptClass ui;
    const std::string supportedFormat = "FAT32";
    constexpr static unsigned char encryptedMediaDescriptor = (unsigned char)0xFA;
    bool isEncrypted(std::string drivePath, bool& isSupportedFormat);
    bool encryptDrive(std::string drivePath);
    bool decryptDrive(std::string drivePath);


    constexpr static int nameMarkEnd = 0x0040 - 1;
    constexpr static int nameMarkStart = nameMarkEnd - 12;
    constexpr static int specialMarkStart = 0x005A;
    constexpr static int specialMarkEnd = 0x005D;
    constexpr static unsigned char specialMarkBytes[4] = { '1', '0', '3', '7' };
    constexpr static unsigned char nameMarkSuffixBytes[9] = { 'l', 'y', 'x', 'y', 'z', '5', '2', '2', '3' };
    constexpr static int markEnd = specialMarkEnd;
    // BPB后12个字节处写入特殊标志
    // 以及修改0x005A-0x005D处的保留字节为特殊标记
    bool detectSpecialMark(unsigned char* bytes, size_t size);
    bool writeSpecialMark(unsigned char* bytes, size_t size);
    bool removeSpecialMark(unsigned char* bytes, size_t size);

    // 使用FSInfo结构中的保留字节作为密码标志
    // FSInfo结构位于第1个FAT表之后的扇区
    // 0x0-0x3: Lead Signature，必须为0x52526141
    // 0x4-0x1E3: 保留字节
    // 0x1E4-0x1E7: Struct Signature，必须为0x72724161
    // 0x1E8-0x1EB: Free Cluster Count
    // 0x1EC-0x1EF: Next Free Cluster
    // 0x1F0-0x1FD: 保留字节
    // 0x1FE-0x1FF: Trail Signature，必须为0x55AA
    bool verifyPasswordMark(unsigned char* bytes, size_t size);
    bool writePasswordMark(unsigned char* bytes, size_t size);
    bool removePasswordMark(unsigned char* bytes, size_t size);

    // BPB的偏移量为0x0015处表示磁盘介质描述符
    // 0xF8: 硬盘、vhd虚拟磁盘文件
    // 0xF9: 双面5.25英寸软盘（15扇区高密度）、双面3.5英寸软盘
    // 0xFA: 双面3.5英寸软盘、RAM虚拟盘
    // 0xFC: 单面5.25英寸软盘（9扇区高密度）、双面8英寸软盘
    // 0xFD: 双面5.25英寸软盘（9扇区低密盘）
    // 0xFE: 单面8英寸软盘（单、双密度）、单面5.25英寸软盘（8扇区低密盘）
    // 0xFF: 双面5.25英寸软盘（8扇区低密盘）
    bool changeMediaDescriptor(unsigned char* bytes, size_t size, unsigned char descriptor);
    unsigned char getMediaDescriptor(unsigned char* bytes, size_t size);

    std::string uiGetSelectedDrivePath() const {
        return ui.comboBoxTargetPartition->currentText().toStdString() + ":\\";
    }
public slots:
    void uiUpdateDriveList();
    void encryptPartition();
    void decryptPartition();
    void formatPartition();
    void ejectDrive();
};

inline std::vector<LoggerSinkPtr> MusicUSBEncrypt::loggerSinks{
    std::make_shared<ConsoleLoggerSink>()
};
inline Logger MusicUSBEncrypt::logger{ "MusicUSBEncrypt", loggerSinks };