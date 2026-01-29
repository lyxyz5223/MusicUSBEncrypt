#include "MusicUSBEncrypt.h"

#include "DriveOperation.h"
#include "EnDecryptor.h"
#include <QMessageBox>

MusicUSBEncrypt::MusicUSBEncrypt(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    uiUpdateDriveList();
}

MusicUSBEncrypt::~MusicUSBEncrypt()
{}


bool MusicUSBEncrypt::isEncrypted(std::string drivePath, bool& isSupportedFormat)
{
    try {
        auto driveType = DriveOperation::getFileSystemType(drivePath);
    }
    catch (std::exception ex) {
        logger.error("Failed to get file system type: {}", ex.what());
        throw;
    }
    catch (...) {
        logger.error("Failed to get file system type for unknown error");
        throw;
    }
    // 以上检验=>驱动器错误或者已加密
    try {
        auto driveType = DriveOperation::detectRawFileSystem(drivePath);
        if (driveType != supportedFormat)
        {
            isSupportedFormat = false;
            return false;
        }
        else
            isSupportedFormat = true;
    }
    catch (std::exception ex) {
        logger.error("Failed to detect raw file system: {}", ex.what());
        throw;
    }
    catch(...) {
        logger.error("Failed to detect raw file system for unknown error");
        throw;
    }
    // 以上检验=>驱动器是有问题的FAT32格式分区
    if (!DriveOperation::processFAT32BootSector(drivePath, [this](unsigned char* bytes, size_t size, bool& write) {
            write = false;
            if (getMediaDescriptor(bytes, size) != encryptedMediaDescriptor)
                return false;
            if (!detectSpecialMark(bytes, size))
                return false;
            return true;
        }))
        return false;
    // 以上检验=>驱动器中指定位置是本程序设置的特殊标志，确实已经加密！
    return true;
}

bool MusicUSBEncrypt::encryptDrive(std::string drivePath)
{
    std::vector<unsigned char> originalBytes; // 拷贝一份
    // 先写入FSInfo中的密码标志
    if (!DriveOperation::processFAT32FSInfoSector(drivePath, [this, &originalBytes](unsigned char* bytes, size_t size, bool& write) {
        write = false;
        std::copy(bytes, bytes + size, std::back_inserter(originalBytes));
        if (!writePasswordMark(bytes, size))
            return false;
        write = true;
        return true;
        }))
        return false;
    // 再写入Boot Sector中的特殊标志，如果失败则恢复FSInfo中的数据
    auto restoreFSInfo = [&drivePath, &originalBytes] {
        DriveOperation::processFAT32FSInfoSector(drivePath, [&originalBytes](unsigned char* bytes, size_t size, bool& write) {
            write = false;
            memcpy(bytes, originalBytes.data(), size);
            write = true;
            return true;
            });
        };
    if (!DriveOperation::processFAT32BootSector(drivePath, [this, &restoreFSInfo](unsigned char* bytes, size_t size, bool& write) {
            write = false;
            if (!writeSpecialMark(bytes, size))
            {
                restoreFSInfo();
                return false; // 返回值传递给调用者，false函数会返回false
            }
            if (!changeMediaDescriptor(bytes, size, encryptedMediaDescriptor))
            {
                restoreFSInfo();
                return false;
            }
            write = true;
            return true;
        }))
        return false;
    return true;
}


bool MusicUSBEncrypt::decryptDrive(std::string drivePath)
{
    // 先校验FSInfo中的密码标志
    if (!DriveOperation::processFAT32FSInfoSector(drivePath, [this](unsigned char* bytes, size_t size, bool& write) {
            write = false;
            if (!verifyPasswordMark(bytes, size))
                return false;
            write = true;
            return true;
        }))
        return false;
    // 再校验并移除Boot Sector中的特殊标志
    if (!DriveOperation::processFAT32BootSector(drivePath, [this](unsigned char* bytes, size_t size, bool& write) {
            write = false;
            if (!removeSpecialMark(bytes, size))
                return false; // 返回值传递给调用者，false函数会返回false
            if (!changeMediaDescriptor(bytes, size, 0xF8))
                return false;
            write = true;
            return true;
        }))
        return false;
    // 最后移除FSInfo中的密码标志
    if (!DriveOperation::processFAT32FSInfoSector(drivePath, [this](unsigned char* bytes, size_t size, bool& write) {
            write = false;
            if (!removePasswordMark(bytes, size))
                return false;
            write = true;
            return true;
        }))
    {
        logger.error("Failed to remove password mark from FSInfo sector after removing special mark from Boot Sector. The drive may be left in an inconsistent state.");
        QMessageBox::critical(this, "Error", tr("清除分区中的密码失败，分区可能会处于不稳定状态。"));
        return false;
    }
    return true;
}

bool MusicUSBEncrypt::detectSpecialMark(unsigned char* bytes, size_t size)
{
    if (bytes == nullptr || size < markEnd)
        return false;
    for (size_t i = 0x5A; i <= 0x5D; ++i) // 遍历比较特殊标记，4次
        if (bytes[i] != specialMarkBytes[i - 0x5A])
            return false;
    return true;
}

bool MusicUSBEncrypt::writeSpecialMark(unsigned char* bytes, size_t size)
{
    // BPB后12个字节处写入特殊标志
    // 以及修改0x005A-0x005D处的保留字节为特殊标记
    if (bytes == nullptr || size < markEnd)
        return false;
    memcpy(bytes + 0x5A, specialMarkBytes, ((size_t)0x5D - 0x5A + 1));
    return true;
}

bool MusicUSBEncrypt::removeSpecialMark(unsigned char* bytes, size_t size)
{
    if (bytes == nullptr || size < markEnd)
        return false;
    memset(bytes + 0x5A, 0, ((size_t)0x5D - 0x5A + 1));
    return true;
}

bool MusicUSBEncrypt::verifyPasswordMark(unsigned char* bytes, size_t size)
{
    if (bytes == nullptr || size < 0x1E3)
        return false;
    std::string password = ui.lineEditPassword->text().toStdString();
    static EnDecryptor encryptor{};
    if (!encryptor.isInitialized())
    {
        if (!encryptor.initialize())
        {
            logger.error("Failed to initialize EnDecryptor for writing password mark.");
            QMessageBox::critical(this, "Error", tr("初始化加解密模块失败！无法进行加解密！"));
            return false;
        }
    }
    // 0x4-0x1E3处为保留字节
    char* hashStart = (char*)(bytes + 0x4);
    constexpr static size_t maxHashLen = ((size_t)0x1E3 - 0x4 + 1);
    size_t hashLen = strlen((char*)bytes);
    bool hashLenOverflow = false;
    if (hashLen > maxHashLen)
    {
        hashLen = maxHashLen; // 防止越界
        hashLenOverflow = true;
    }
    auto hashedPassword = std::string(hashStart, hashLen);
    bool success = encryptor.verifyPassword(password, hashedPassword);
    if (!success && hashLenOverflow)
        // 密码可能过长，尝试简单等长加密验证
        success = encryptor.verifyLengthEqualEncryptPassword(password, hashedPassword);
    if (!success)
    {
        logger.error("Password verification failed. Please check your password and try again.");
        QMessageBox::critical(this, "Error", tr("密码错误！请重试。"));
    }
    return success;
}

bool MusicUSBEncrypt::writePasswordMark(unsigned char* bytes, size_t size)
{
    if (bytes == nullptr || size < 0x1E3)
        return false;
    std::string password = ui.lineEditPassword->text().toStdString();
    static EnDecryptor encryptor{};
    if (!encryptor.isInitialized())
    {
        if (!encryptor.initialize())
        {
            logger.error("Failed to initialize EnDecryptor for writing password mark.");
            QMessageBox::critical(this, "Error", tr("初始化加解密模块失败！无法进行加解密！"));
            return false;
        }
    }
    // 0x4-0x1E3处为保留字节
    char* hashStart = (char*)(bytes + 0x4);
    constexpr static size_t maxHashLen = ((size_t)0x1E3 - 0x4 + 1);
    memset(hashStart, 0, maxHashLen);
    std::string hashCode = encryptor.hashPassword(password);
    password.clear(); // 清除密码内存
    if (hashCode.size() > maxHashLen)
    {
        // 密码过长，进行简单等长加密
        hashCode = encryptor.lengthEqualEncryptPassword(password);
        logger.warning("Password is too long, using length-equal encryption for password mark.");
    }
    memcpy(hashStart, hashCode.c_str(), hashCode.size());
    return true;
}

bool MusicUSBEncrypt::removePasswordMark(unsigned char* bytes, size_t size)
{
    if (bytes == nullptr || size < 0x1E3)
        return false;
    constexpr static size_t maxHashLen = ((size_t)0x1E3 - 0x4 + 1);
    char* hashStart = (char*)(bytes + 0x4);
    //bool success = verifyPasswordMark(bytes, size);
    //if (!success)
    //    return false;
    memset(hashStart, 0, maxHashLen);
    return true;
}

bool MusicUSBEncrypt::changeMediaDescriptor(unsigned char* bytes, size_t size, unsigned char descriptor)
{
    if (bytes == nullptr || size < 0x16)
        return false;
    bytes[0x15] = descriptor;
    return true;
}

unsigned char MusicUSBEncrypt::getMediaDescriptor(unsigned char* bytes, size_t size)
{
    if (bytes == nullptr || size < 0x16)
        return 0;
    return bytes[0x15];
}

void MusicUSBEncrypt::encryptPartition()
{
    std::string drivePath = ui.comboBoxTargetPartition->currentText().toStdString() + ":\\";
    try {
        bool isSupportedFormat = false;
        if (isEncrypted(drivePath, isSupportedFormat))
            logger.warning("Selected partition is already encrypted.");
        else
        {
            logger.info("Selected partition is not encrypted.");
            if (isSupportedFormat)
            {
                if (encryptDrive(drivePath))
                {
                    logger.info("Successfully encrypted the selected partition.");
                    QMessageBox::information(this, "Success", tr("成功加密所选分区！"));
                }
                else
                {
                    logger.error("Failed to encrypt the selected partition.");
                    QMessageBox::critical(this, "Error", tr("加密所选分区失败！"));
                }
            }
        }
    }
    catch (...) {}
}

void MusicUSBEncrypt::decryptPartition()
{
    std::string drivePath = ui.comboBoxTargetPartition->currentText().toStdString() + ":\\";
    try {
        bool isSupportedFormat = false;
        if (isEncrypted(drivePath, isSupportedFormat))
        {
            logger.info("Selected partition is encrypted.");
            if (isSupportedFormat)
            {
                if (decryptDrive(drivePath))
                {
                    logger.info("Successfully decrypted the selected partition.");
                    QMessageBox::information(this, "Success", tr("成功解密所选分区！"));
                }
                else
                {
                    logger.error("Failed to decrypt the selected partition.");
                    QMessageBox::critical(this, "Error", tr("解密所选分区失败！"));
                }
            }
        }
        else
            logger.warning("Selected partition is not encrypted.");
    }
    catch (...) {}
}

void MusicUSBEncrypt::formatPartition()
{
    std::string drivePath = ui.comboBoxTargetPartition->currentText().toStdString() + ":\\";
    DriveOperation::formatPartition(drivePath, supportedFormat, true);
}

void MusicUSBEncrypt::ejectDrive()
{
    std::string drivePath = ui.comboBoxTargetPartition->currentText().toStdString() + ":\\";
    bool result = DriveOperation::ejectDrive(drivePath);
    if (result)
    {
        logger.info("Successfully ejected the selected drive.");
        QMessageBox::information(this, "Success", tr("成功弹出所选驱动器！"));
    }
    else
    {
        logger.error("Failed to eject the selected drive.");
        QMessageBox::critical(this, "Error", tr("弹出所选驱动器失败！"));
    }
}

void MusicUSBEncrypt::uiUpdateDriveList()
{
    auto&& driveList = DriveOperation::getLogicalPartitions();
    ui.comboBoxTargetPartition->clear();
    for (const auto& drive : driveList)
    {
        auto letter = drive.driveLetter;
        if (letter == 0)
            continue;
        ui.comboBoxTargetPartition->addItem(QString((char)letter));
        logger.info("Found logical partition: {}", (char)letter);
    }
}


