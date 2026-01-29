#pragma once
#include <vector>
#include <Logger.h>
#include <Windows.h>
struct VolumeExtent {
    DWORD diskNumber;
    long long startingOffset;
    long long extentLength;
};

struct PartitionInfo {
    DWORD partitionCount{ 0 };
    DWORD partitionNumber{ 0 };
    LARGE_INTEGER partitionLength{ 0 };
    LARGE_INTEGER startingOffset{ 0 };
    PARTITION_STYLE partitionStyle;
    GUID partitionId;
    GUID partitionType;
    unsigned char driveLetter{ 0 }; // 'A' - 'Z'
    union {
        PARTITION_INFORMATION_MBR Mbr;
        PARTITION_INFORMATION_GPT Gpt;
    };
};

struct DiskInfo {
    DWORD physicalNumber{ 0 }; // 仅当devicePath不为空时有效
    std::string deviceId;
    std::string devicePath;
    std::string description;
    std::string hardwareId;
    std::string friendlyName;
    std::vector<PartitionInfo> partitions;
};

class DriveOperation
{
    static std::vector<LoggerSinkPtr> loggerSinks;
    static Logger logger;
public:
    // \param drivePath 分区路径，如"D:\"或者"D:\xxxxx\xxx"，注意：必须是分区路径，不能是物理磁盘路径，否则将返回空字符串
    // 如果无法确定文件系统类型，返回空字符串
    static std::string getFileSystemType(std::string drivePath);
    /**
    * \param drivePath 分区路径，如"D:\"或者"D:"，注意：必须是分区路径，不能是物理磁盘路径，否则将抛出std::invalid_argument错误
    * \note 如果无法打开设备，抛出std::runtime_error错误
    * \note 如果分区路径有误，抛出std::invalid_argument错误
    */
    static std::string detectRawFileSystem(const std::string& drivePath);

    static std::vector<unsigned char> readRawSector(const std::string& drivePath, DWORD sectorNumber, DWORD sectorCount = 1, DWORD* outSectorSize = nullptr);

    static void writeRawSector(const std::string& drivePath, BYTE* buffer, size_t bufferSize, DWORD sectorNumber, DWORD sectorSize);

    static bool formatPartition(const std::string& drivePath, const std::string& fileSystem = "FAT32", bool quickFormat = true);

    static bool ejectDrive(const std::string& drivePath);

    // Boot Sector(BPB) 解析与写入
    static bool processFAT32BootSector(const std::string& drivePath, std::function<bool(BYTE* buffer, size_t bufferSize, bool& writeFlag)> handler);

    static bool processFAT32FSInfoSector(const std::string& drivePath, std::function<bool(BYTE* buffer, size_t bufferSize, bool& writeFlag)> handler);

    // 获取系统中所有逻辑分区路径
    static std::vector<PartitionInfo> getLogicalPartitions();

    static std::string getPhysicalDiskPathFromPhysicalNumber(DWORD physicalNumber) {
        return "\\\\.\\PhysicalDrive" + std::to_string(physicalNumber);
    }
    static std::string getVolumePathFromPartitionPath(const std::string& partitionPath) {
        if (!checkPartitionPath(partitionPath))
            throw std::invalid_argument("Invalid partition path");
        return "\\\\.\\" + partitionPath.substr(0, 2);
    }
    //static unsigned char getDriveLetterFromPartitionNumber(DWORD partitionNumber) {
    //    return partitionNumber + 'A';
    //}

    static unsigned char getDriveLetterByPartitionOffset(int diskNumber, LARGE_INTEGER partitionOffset);

private:
    static std::vector<DiskInfo> getPhysicalDiskInfo();
    static void printPhysicalDiskInfo();
    static void printPartitionInfo();
    static void printDiskInfoByWMI();
    

    // 获取物理磁盘下的所有逻辑分区路径
    static std::vector<PartitionInfo> getLogicalPartitions(DWORD physicalNumber, HANDLE device = INVALID_HANDLE_VALUE);
    
private:
    static void ensurePathCompletion(std::string& path);
    // 失败返回0
    static DWORD getSectorSize(HANDLE hDevice);
    static std::string analyzeFileSystemSignature(BYTE* buffer, size_t size);
    static bool isLetter(char ch) {
        if (ch >= 'A' && ch <= 'Z') return true;
        else if (ch >= 'a' && ch <= 'z') return true;
        else return false;
    }
    static bool checkPartitionPath(const std::string& path) {
        // 格式必须是 "X:\" 或者 "X:"
        if (path.size() < 2 || !isLetter(path[0]) || path[1] != ':') return false;
        return true;
    }
};


inline std::vector<LoggerSinkPtr> DriveOperation::loggerSinks{
    std::make_shared<ConsoleLoggerSink>()
};
inline Logger DriveOperation::logger{ "DriveOperation", loggerSinks };