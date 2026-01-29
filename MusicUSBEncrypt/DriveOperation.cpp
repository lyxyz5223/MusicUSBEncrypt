#include "DriveOperation.h"
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <vector>
#include <iomanip>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
// 使用WMI获取更详细的磁盘信息
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#include <StringProcess.h>
//#include <span>
#include <shlobj.h>
#include <shlwapi.h>

#include <windows.h>
#include <winioctl.h>
#include <vector>
#include <string>
#include <iostream>



std::vector<DiskInfo> DriveOperation::getPhysicalDiskInfo()
{
    std::vector<DiskInfo> disks;
    // 获取磁盘设备列表
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_DISK, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDevInfo == INVALID_HANDLE_VALUE)
    {
        logger.error() << "SetupDiGetClassDevs 失败: " << GetLastError();
        return disks;
    }
    SP_DEVICE_INTERFACE_DATA interfaceData = {};
    interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    for (DWORD memberIndex = 0; SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &GUID_DEVINTERFACE_DISK, memberIndex, &interfaceData); ++memberIndex)
    {
        disks.emplace_back();
        DiskInfo& disk = disks.back();
        // 获取接口详情（设备路径）
        DWORD requiredLength = 0;
        SetupDiGetDeviceInterfaceDetail(hDevInfo, &interfaceData, NULL, 0, &requiredLength, NULL);
        if (requiredLength <= 0)
        {
            disks.pop_back();
            continue;
        }
        std::vector<BYTE> detailBuffer(requiredLength);
        PSP_DEVICE_INTERFACE_DETAIL_DATA pDetail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)detailBuffer.data();
        pDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        SP_DEVINFO_DATA devInfoData = {};
        devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiGetDeviceInterfaceDetail(hDevInfo, &interfaceData, pDetail, requiredLength, NULL, &devInfoData))
        {
            disks.pop_back();
            continue;
        }
        disk.devicePath = wstr2str_2UTF8(pDetail->DevicePath);

        // 获取设备实例ID
        CHAR deviceId[MAX_PATH] = { 0 };
        if (SetupDiGetDeviceInstanceIdA(hDevInfo, &devInfoData, deviceId, MAX_PATH, nullptr))
            disk.deviceId = deviceId;
        // 获取设备描述（更详细的）
        WCHAR buffer[512] = { 0 };
        // 获取友好名称
        if (SetupDiGetDeviceRegistryProperty(hDevInfo, &devInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)buffer, sizeof(buffer), NULL))
            disk.friendlyName = wstr2str_2UTF8(buffer);
        // 获取设备描述
        if (SetupDiGetDeviceRegistryProperty(hDevInfo, &devInfoData, SPDRP_DEVICEDESC, NULL, (PBYTE)buffer, sizeof(buffer), NULL))
            disk.description = wstr2str_2UTF8(buffer);
        // 获取硬件ID
        DWORD dataType = 0;
        DWORD idBufferSize = 0;
        SetupDiGetDeviceRegistryProperty(hDevInfo, &devInfoData, SPDRP_HARDWAREID, &dataType, NULL, 0, &idBufferSize);
        if (idBufferSize > 0)
        {
            std::unique_ptr<char[]> hwBuffer = std::make_unique<char[]>(idBufferSize);
            if (SetupDiGetDeviceRegistryProperty(hDevInfo, &devInfoData, SPDRP_HARDWAREID, &dataType, (PBYTE)hwBuffer.get(), idBufferSize, NULL))
                disk.hardwareId = wstr2str_2UTF8((wchar_t*)hwBuffer.get());
        }

        // 打开设备句柄（Setup API 只能拿到路径，分区要用 DeviceIoControl）
        HANDLE hDevice = CreateFileW(pDetail->DevicePath,
            0/*GENERIC_READ*/,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);

        if (hDevice == INVALID_HANDLE_VALUE)
            continue;

        // 获取 Physical Number（确认是 PhysicalDriveX 中的哪个）
        STORAGE_DEVICE_NUMBER sdn = {};
        DWORD bytesReturned = 0;
        if (DeviceIoControl(hDevice, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sdn, sizeof(sdn), &bytesReturned, NULL))
        {
            disk.physicalNumber = sdn.DeviceNumber;
            auto physicalDiskPath = getPhysicalDiskPathFromPhysicalNumber(sdn.DeviceNumber);
            disk.partitions = getLogicalPartitions(sdn.DeviceNumber, hDevice);
        }

    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return disks;
}

void DriveOperation::printPhysicalDiskInfo()
{
    logger.info() << "=== 磁盘设备信息 ===";
    auto disks = getPhysicalDiskInfo();
    for (const auto& disk : disks)
    {
        logger.info() << "磁盘设备:";
        logger.info() << "  设备ID: " << disk.deviceId;
        logger.info() << "  描述: " << disk.description;
        logger.info() << "  友好名称: " << disk.friendlyName;
        if (!disk.hardwareId.empty())
            logger.info() << "  硬件ID: " << disk.hardwareId;
    }
}
void DriveOperation::printPartitionInfo()
{
    // 获取所有逻辑驱动器
    DWORD drives = GetLogicalDrives();
    char driveLetter = 'A';

    logger.info() << "=== 逻辑分区信息 ===";

    while (drives) {
        if (drives & 1) {
            char rootPath[4] = { driveLetter, ':', '\\', '\0' };

            // 获取驱动器类型
            UINT type = GetDriveTypeA(rootPath);
            std::string typeStr;
            switch (type) {
            case DRIVE_FIXED:       typeStr = "固定磁盘"; break;
            case DRIVE_REMOVABLE:   typeStr = "可移动磁盘"; break;
            case DRIVE_CDROM:       typeStr = "CD/DVD"; break;
            case DRIVE_REMOTE:      typeStr = "网络驱动器"; break;
            case DRIVE_RAMDISK:     typeStr = "RAM磁盘"; break;
            default:                typeStr = "未知";
            }

            // 获取卷标和序列号
            char volumeName[MAX_PATH] = { 0 };
            char fileSystemName[MAX_PATH] = { 0 };
            DWORD serialNumber = 0, maxComponentLen = 0, fileSystemFlags = 0;

            if (GetVolumeInformationA(
                rootPath,
                volumeName, sizeof(volumeName),
                &serialNumber,
                &maxComponentLen,
                &fileSystemFlags,
                fileSystemName, sizeof(fileSystemName))) {

                logger.info() << "驱动器 " << driveLetter << ":\\";
                logger.info() << "  类型: " << typeStr;
                logger.info() << "  卷标: " << (strlen(volumeName) > 0 ? ANSIToUTF8(volumeName) : "(无)");
                logger.info() << "  文件系统: " << fileSystemName;
                logger.info() << "  序列号: " << std::hex << serialNumber << std::dec;

                // 获取磁盘空间
                ULARGE_INTEGER freeBytes, totalBytes, totalFreeBytes;
                if (GetDiskFreeSpaceExA(rootPath, &freeBytes, &totalBytes, &totalFreeBytes))
                {
                    logger.info() << "  总空间: " << std::fixed << std::setprecision(2)
                        << totalBytes.QuadPart / (1024.0 * 1024 * 1024) << " GB";
                    logger.info() << "  可用空间: " << freeBytes.QuadPart / (1024.0 * 1024 * 1024) << " GB";
                    logger.info() << "  使用率: "
                        << (1.0 - (double)freeBytes.QuadPart / totalBytes.QuadPart) * 100
                        << "%";
                }
            }
        }
        driveLetter++;
        drives >>= 1;
    }
}
void DriveOperation::printDiskInfoByWMI()
{
    HRESULT hres;

    // 初始化COM
    //hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    //if (FAILED(hres)) return;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (SUCCEEDED(hres)) {
        IWbemServices* pSvc = NULL;
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL,
            0, NULL, 0, 0, &pSvc);

        if (SUCCEEDED(hres)) {
            // 设置代理安全级别
            hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

            if (SUCCEEDED(hres)) {
                logger.info() << "=== WMI磁盘信息 ===";

                // 查询物理磁盘
                IEnumWbemClassObject* pEnumerator = NULL;
                hres = pSvc->ExecQuery(bstr_t("WQL"),
                    bstr_t("SELECT * FROM Win32_DiskDrive"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    NULL, &pEnumerator);

                if (SUCCEEDED(hres)) {
                    IWbemClassObject* pclsObj = NULL;
                    ULONG uReturn = 0;

                    while (pEnumerator) {
                        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                        if (uReturn == 0) break;

                        VARIANT vtProp;

                        // 设备ID
                        hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
                        if (SUCCEEDED(hr)) {
                            logger.info() << "设备ID: " << ANSIToUTF8(_com_util::ConvertBSTRToString(vtProp.bstrVal));
                            VariantClear(&vtProp);
                        }

                        // 型号
                        hr = pclsObj->Get(L"Model", 0, &vtProp, 0, 0);
                        if (SUCCEEDED(hr)) {
                            logger.info() << "型号: " << ANSIToUTF8(_com_util::ConvertBSTRToString(vtProp.bstrVal));
                            VariantClear(&vtProp);
                        }

                        // 接口类型
                        hr = pclsObj->Get(L"InterfaceType", 0, &vtProp, 0, 0);
                        if (SUCCEEDED(hr)) {
                            logger.info() << "接口: " << ANSIToUTF8(_com_util::ConvertBSTRToString(vtProp.bstrVal));
                            VariantClear(&vtProp);
                        }

                        // 序列号
                        hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
                        if (SUCCEEDED(hr)) {
                            logger.info() << "序列号: " <<
                                (vtProp.vt == VT_NULL ? "(无)" : ANSIToUTF8(_com_util::ConvertBSTRToString(vtProp.bstrVal)));
                            VariantClear(&vtProp);
                        }

                        // 容量
                        hr = pclsObj->Get(L"Size", 0, &vtProp, 0, 0);
                        if (SUCCEEDED(hr) && vtProp.vt != VT_NULL) {
                            ULONGLONG size = _wtoi64(vtProp.bstrVal);
                            logger.info() << "容量: " << size / (1024LL * 1024 * 1024) << " GB";
                            VariantClear(&vtProp);
                        }

                        // 分区数
                        hr = pclsObj->Get(L"Partitions", 0, &vtProp, 0, 0);
                        if (SUCCEEDED(hr) && vtProp.vt != VT_NULL) {
                            logger.info() << "分区数: " << vtProp.intVal;
                            VariantClear(&vtProp);
                        }

                        pclsObj->Release();
                    }

                    pEnumerator->Release();
                }

                // 查询分区信息
                logger.info() << "=== WMI分区信息 ===";
                pEnumerator = NULL;
                hres = pSvc->ExecQuery(bstr_t("WQL"),
                    bstr_t("SELECT * FROM Win32_LogicalDisk"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    NULL, &pEnumerator);

                if (SUCCEEDED(hres)) {
                    IWbemClassObject* pclsObj = NULL;
                    ULONG uReturn = 0;

                    while (pEnumerator) {
                        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                        if (uReturn == 0) break;

                        VARIANT vtProp;

                        hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
                        if (SUCCEEDED(hr)) {
                            logger.info() << "分区: " << ANSIToUTF8(_com_util::ConvertBSTRToString(vtProp.bstrVal));
                            VariantClear(&vtProp);
                        }

                        hr = pclsObj->Get(L"VolumeName", 0, &vtProp, 0, 0);
                        if (SUCCEEDED(hr)) {
                            logger.info() << "卷标: " <<
                                (vtProp.vt == VT_NULL ? "(无)" : ANSIToUTF8(_com_util::ConvertBSTRToString(vtProp.bstrVal)));
                            VariantClear(&vtProp);
                        }

                        hr = pclsObj->Get(L"FileSystem", 0, &vtProp, 0, 0);
                        if (SUCCEEDED(hr)) {
                            logger.info() << "文件系统: " <<
                                (vtProp.vt == VT_NULL ? "(无)" : ANSIToUTF8(_com_util::ConvertBSTRToString(vtProp.bstrVal)));
                            VariantClear(&vtProp);
                        }

                        pclsObj->Release();
                    }

                    pEnumerator->Release();
                }
            }
            pSvc->Release();
        }
        pLoc->Release();
    }

    CoUninitialize();
}



std::vector<PartitionInfo> DriveOperation::getLogicalPartitions(DWORD physicalNumber, HANDLE device)
{
    HANDLE& hDevice = device;
    std::vector<PartitionInfo> rst;
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        hDevice = CreateFileA(getPhysicalDiskPathFromPhysicalNumber(physicalNumber).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDevice == INVALID_HANDLE_VALUE)
            return rst;
    }
    // 获取磁盘布局
    DWORD layoutSize = 0;
    std::vector<BYTE> buffer(512);
    DRIVE_LAYOUT_INFORMATION_EX* layout = (DRIVE_LAYOUT_INFORMATION_EX*)buffer.data();
    while (!layoutSize)
    {
        if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, layout, buffer.size(), &layoutSize, NULL))
            break;
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            break;
        buffer.resize(buffer.size() * 2);
        layout = (DRIVE_LAYOUT_INFORMATION_EX*)buffer.data();
    }
    if (layoutSize <= 0)
    {
        auto code = GetLastError();
        CloseHandle(hDevice);
        return rst;
    }

    switch (layout->PartitionStyle)
    {
    case PARTITION_STYLE_MBR:
        for (DWORD i = 0; i < layout->PartitionCount; ++i)
        {
            const PARTITION_INFORMATION_EX& part = layout->PartitionEntry[i];
            PartitionInfo partInfo;
            memset(&partInfo, 0, sizeof(partInfo));
            partInfo.partitionStyle = (PARTITION_STYLE)layout->PartitionStyle;
            partInfo.partitionCount = layout->PartitionCount;
            partInfo.partitionNumber = part.PartitionNumber;
            partInfo.partitionLength = part.PartitionLength;
            partInfo.startingOffset = part.StartingOffset;
            partInfo.partitionId = part.Mbr.PartitionId;
            ((BYTE*)&partInfo.partitionType)[sizeof(partInfo.partitionType) - 1] = part.Mbr.PartitionType;
            partInfo.driveLetter = getDriveLetterByPartitionOffset(physicalNumber, part.StartingOffset);
            partInfo.Mbr = part.Mbr;
            rst.push_back(partInfo);
        }
        break;
    case PARTITION_STYLE_GPT:
        for (DWORD i = 0; i < layout->PartitionCount; ++i)
        {
            const PARTITION_INFORMATION_EX& part = layout->PartitionEntry[i];
            PartitionInfo partInfo;
            memset(&partInfo, 0, sizeof(partInfo));
            partInfo.partitionStyle = (PARTITION_STYLE)layout->PartitionStyle;
            partInfo.partitionCount = layout->PartitionCount;
            partInfo.partitionNumber = part.PartitionNumber;
            partInfo.partitionLength = part.PartitionLength;
            partInfo.startingOffset = part.StartingOffset;
            partInfo.partitionId = part.Gpt.PartitionId;
            partInfo.partitionType = part.Gpt.PartitionType;
            partInfo.driveLetter = getDriveLetterByPartitionOffset(physicalNumber, part.StartingOffset);
            partInfo.Gpt = part.Gpt;
            rst.push_back(partInfo);
        }
        break;
    case PARTITION_STYLE_RAW:
        for (DWORD i = 0; i < layout->PartitionCount; ++i)
        {
            const PARTITION_INFORMATION_EX& part = layout->PartitionEntry[i];
            PartitionInfo partInfo;
            memset(&partInfo, 0, sizeof(partInfo));
            partInfo.partitionStyle = (PARTITION_STYLE)layout->PartitionStyle;
            partInfo.partitionCount = layout->PartitionCount;
            partInfo.partitionNumber = part.PartitionNumber;
            partInfo.partitionLength = part.PartitionLength;
            partInfo.startingOffset = part.StartingOffset;
            partInfo.driveLetter = getDriveLetterByPartitionOffset(physicalNumber, part.StartingOffset);
            rst.push_back(partInfo);
        }
        break;
    }
    CloseHandle(hDevice);
    return rst;
}


unsigned char DriveOperation::getDriveLetterByPartitionOffset(int diskNumber, LARGE_INTEGER partitionOffset)
{
    DWORD drives = GetLogicalDrives();
    for (char driveLetter = 'A'; driveLetter <= 'Z'; ++driveLetter)
    {
        if (!(drives & 1))
        {
            drives >>= 1;
            continue;
        }
        std::string path = getVolumePathFromPartitionPath(driveLetter + std::string(":\\"));
        HANDLE h = CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE)
        {
            drives >>= 1;
            continue;
        }
        VOLUME_DISK_EXTENTS extents;
        DWORD bytes;
        if (!DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, &extents, sizeof(extents), &bytes, NULL))
        {
            drives >>= 1;
            continue;
        }
        for (size_t i = 0; i < extents.NumberOfDiskExtents; ++i)
        {
            if (extents.Extents[i].DiskNumber == diskNumber
                && extents.Extents->StartingOffset.QuadPart == partitionOffset.QuadPart)
            {
                CloseHandle(h);
                return driveLetter;
            }
        }
        CloseHandle(h);
        drives >>= 1;
    }
    return 0;
}

std::vector<PartitionInfo> DriveOperation::getLogicalPartitions()
{
    auto&& disks = getPhysicalDiskInfo();
    std::vector<PartitionInfo> allPartitions;
    for (const auto& disk : disks)
    {
        for (const auto& part : disk.partitions)
            allPartitions.push_back(part);
    }
    return allPartitions;
}

std::string DriveOperation::getFileSystemType(std::string drivePath)
{
    if (drivePath.size() < 2) 
        throw std::invalid_argument("Invalid drive path");
    ensurePathCompletion(drivePath);
    char fileSystemName[MAX_PATH + 1];
    memset(fileSystemName, 0, MAX_PATH + 1);
    DWORD serialNumber = 0, maxComponentLen = 0, fileSystemFlags = 0;
    if (GetVolumeInformationA(
        drivePath.c_str(), // 驱动器路径，如 "C:\\"
        NULL, 0, // 卷标
        &serialNumber, // 序列号
        &maxComponentLen, // 最大文件名长度
        &fileSystemFlags, // 文件系统标志
        fileSystemName, // 文件系统名称
        sizeof(fileSystemName)
    )) return fileSystemName; // 返回"NTFS","FAT32","exFAT"等
    return "";
}


// 识别RAW格式文件系统
std::string DriveOperation::detectRawFileSystem(const std::string& drivePath)
{
    DWORD sectorSize = 0;
    auto&& sector0 = readRawSector(drivePath, 0, 1, &sectorSize); // 读取第0扇区
    // 检查文件系统签名
    return analyzeFileSystemSignature(sector0.data(), sectorSize);
}

std::vector<unsigned char> DriveOperation::readRawSector(const std::string& drivePath, DWORD sectorNumber, DWORD sectorCount, DWORD* outSectorSize)
{
    if (!checkPartitionPath(drivePath))
        throw std::invalid_argument("Invalid drive path");
    HANDLE hDevice = CreateFileA(getVolumePathFromPartitionPath(drivePath).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
        throw std::runtime_error("Failed to execute \"CreateFile\" function.");
    // 读取MBR/GPT
    auto sectorSize = getSectorSize(hDevice); // 获取扇区大小（字节）
    if (sectorSize == 0) // 扇区大小获取失败
        sectorSize = 512; // 采用默认值
    *outSectorSize = sectorSize; // 设置输出扇区大小
    LARGE_INTEGER offset = { 0 };
    offset.QuadPart = sectorNumber * sectorSize;
    if (!SetFilePointerEx(hDevice, offset, NULL, FILE_BEGIN))
    {
        CloseHandle(hDevice);
        throw std::runtime_error("Failed to set file pointer.");
    }
    std::vector<BYTE> buffer(sectorSize, 0);
    DWORD bytesRead;
    if (!ReadFile(hDevice, buffer.data(), sectorSize, &bytesRead, NULL))
    {
        CloseHandle(hDevice);
        throw std::runtime_error("Failed to read file.");
    }
    CloseHandle(hDevice);
    return buffer;
}

void DriveOperation::writeRawSector(const std::string& drivePath, BYTE* buffer, size_t bufferSize, DWORD sectorNumber, DWORD sectorSize)
{
    if (!checkPartitionPath(drivePath))
        throw std::invalid_argument("Invalid drive path");
    HANDLE hDevice = CreateFileA(getVolumePathFromPartitionPath(drivePath).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
        throw std::runtime_error("Failed to execute \"CreateFile\" function.");
    // 读取MBR/GPT
    LARGE_INTEGER offset = { 0 };
    offset.QuadPart = ((long long)sectorNumber) * sectorSize;
    if (!SetFilePointerEx(hDevice, offset, NULL, FILE_BEGIN))
    {
        CloseHandle(hDevice);
        throw std::runtime_error("Failed to set file pointer.");
    }
    DWORD bytesWritten;
    if (!WriteFile(hDevice, buffer, bufferSize, &bytesWritten, NULL))
    {
        CloseHandle(hDevice);
        throw std::runtime_error("Failed to read file.");
    }
    CloseHandle(hDevice);
}


bool DriveOperation::formatPartition(const std::string& drivePath, const std::string& fileSystem, bool quickFormat)
{
    UINT driveIndex = toupper(drivePath[0]) - 'A';
    auto rst = SHFormatDrive(NULL, driveIndex, SHFMT_ID_DEFAULT, quickFormat ? 0 : SHFMT_OPT_FULL);
    if (rst == SHFMT_ERROR || rst == SHFMT_CANCEL || rst == SHFMT_NOFORMAT)
        return false;
    return true;
}

bool DriveOperation::ejectDrive(const std::string& drivePath)
{
    std::string volumePath = getVolumePathFromPartitionPath(drivePath);

    HANDLE hVolume = CreateFileA(volumePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVolume == INVALID_HANDLE_VALUE)
        return false;
    DWORD bytesReturned;
    // 锁定卷（防止写入）
    if (!DeviceIoControl(hVolume, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        CloseHandle(hVolume);
        logger.error() << "锁定卷失败，错误码: " << GetLastError();
        return false;
    }
    // 卸载文件系统
    if (!DeviceIoControl(hVolume, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        CloseHandle(hVolume);
        logger.error() << "卸载卷失败，错误码: " << GetLastError();
        return false;
    }
    // 弹出设备
    PREVENT_MEDIA_REMOVAL pmr = { FALSE };
    if (!DeviceIoControl(hVolume, IOCTL_STORAGE_MEDIA_REMOVAL, &pmr, sizeof(pmr), NULL, 0, &bytesReturned, NULL))
    {
        CloseHandle(hVolume);
        logger.error() << "允许弹出失败，错误码: " << GetLastError();
        return false;
    }
    if (!DeviceIoControl(hVolume, IOCTL_STORAGE_EJECT_MEDIA, NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        CloseHandle(hVolume);
        logger.error() << "弹出失败，错误码: " << GetLastError();
        return false;
    }
    CloseHandle(hVolume);
    return true;
}

bool DriveOperation::processFAT32BootSector(const std::string& drivePath, std::function<bool(BYTE* buffer, size_t bufferSize, bool& writeFlag)> handler)
{
    try {
        DWORD sectorSize = 0;
        auto&& buffer = readRawSector(drivePath, 0, 1, &sectorSize);
        bool writeFlag = false;
        bool rst = handler(buffer.data(), buffer.size(), writeFlag);
        if (writeFlag) // 需要写回
            writeRawSector(drivePath, buffer.data(), buffer.size(), 0, sectorSize);
        if (!rst)
            return false;
    } catch(...) {
        logger.error() << "读取FAT32引导扇区失败。";
        return false;
    }
    return true;
}

bool DriveOperation::processFAT32FSInfoSector(const std::string& drivePath, std::function<bool(BYTE* buffer, size_t bufferSize, bool& writeFlag)> handler)
{
    try {
        DWORD sectorSize = 0;
        auto&& buffer = readRawSector(drivePath, 1, 1, &sectorSize);
        bool writeFlag = false;
        bool rst = handler(buffer.data(), buffer.size(), writeFlag);
        if (writeFlag) // 需要写回
            writeRawSector(drivePath, buffer.data(), buffer.size(), 1, sectorSize);
        if (!rst)
            return false;
    }
    catch (...) {
        logger.error() << "读取FAT32引导扇区失败。";
        return false;
    }
    return true;
}

void DriveOperation::ensurePathCompletion(std::string& path)
{
    if (path.back() != '\\' && path.back() != '/')
        path += '\\';
}

DWORD DriveOperation::getSectorSize(HANDLE hDevice)
{
    // 获取磁盘几何信息（获取逻辑扇区大小）
    DISK_GEOMETRY_EX geo = { 0 };
    DWORD bytesReturned = 0;
    BOOL geoResult = DeviceIoControl(
        hDevice,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        NULL, 0,
        &geo, sizeof(geo),
        &bytesReturned,
        NULL
    );
    DWORD sectorSize = 0;
    if (geoResult)
        sectorSize = geo.Geometry.BytesPerSector;
    return sectorSize;
}

// 文件系统签名分析
std::string DriveOperation::analyzeFileSystemSignature(BYTE* bytes, size_t size)
{
    //std::span<BYTE> buffer(bytes, size);
    BYTE* buffer = bytes;
    // NTFS签名: "NTFS    "
    if (memcmp(buffer + 3, "NTFS", 4) == 0) return "NTFS";

    // FAT32签名
    if (buffer[510] == 0x55
        && buffer[511] == 0xAA) // 结束标志，占2字节，0x55AA
    {
        // 检查FAT类型
        uint16_t bytesPerSector = *(uint16_t*)(buffer + 0x0B); // 每个扇区字节数，占2字节
        uint8_t sectorsPerCluster = buffer[0x0D]; // 每簇扇区数，占1字节
        uint16_t reservedSectors = *(uint16_t*)(buffer + 0x0E); // 保留扇区数，占2字节
        uint8_t fatCopies = buffer[0x10]; // FAT表数，占1字节
        // 计算总簇数
        uint32_t rootEntryCount = *(uint16_t*)(buffer + 0x11); // 根目录条目数(unused)，占2字节
        uint32_t totalSectors16 = *(uint16_t*)(buffer + 0x13); // sectors(Small volume),在偏移19处，占4字节
        uint32_t totalSectors32 = *(uint32_t*)(buffer + 0x20); // sectors(Large volume),在偏移32处，占4字节
        uint32_t fatSize16 = *(uint16_t*)(buffer + 0x16); // Sectors per FAT(Small volume),每个FAT表扇区数，占2字节
        uint32_t fatSize32 = *(uint32_t*)(buffer + 0x24); // Sectors per FAT(Large volume),每个FAT表扇区数，占4字节
        uint32_t fatSize = fatSize16 ? fatSize16 : fatSize32; // 获取FAT表扇区数
        uint32_t totalSectors = totalSectors16 ? totalSectors16 : totalSectors32; // 获取总扇区数
        // 基础有效性检查
        if (bytesPerSector != 0 && sectorsPerCluster != 0 && fatCopies != 0&& totalSectors != 0)
        {
            // 计算数据扇区数（FAT12/16方法，假设是FAT16）
            // FAT32特征：根目录条目数为0且使用32位总扇区数
            uint8_t isFat32 = (rootEntryCount == 0);
            uint32_t rootDirSectors = 0;
            if (!isFat32)
                rootDirSectors = ((rootEntryCount * 32) + bytesPerSector - 1) / bytesPerSector;
            uint32_t dataSectors = totalSectors - (reservedSectors + (fatCopies * fatSize) + rootDirSectors);
            uint32_t clusters = dataSectors / sectorsPerCluster;
            // 根据簇数判断
            if (clusters < 4085)
                return "FAT12";
            else if (clusters < 65525)
                return "FAT16";
            else
                return "FAT32";
        }
    }

    // exFAT签名: "EXFAT   "
    if (memcmp(buffer + 3, "EXFAT", 5) == 0) return "exFAT";

    if (memcmp(buffer + 82, "FAT", 3) == 0) return "FAT";

    if (memcmp(buffer, "XFSB", 4) == 0) return "XFS";

    // EXT系列签名
    if (*(uint16_t*)(buffer + 1080) == 0xEF53) return "EXT2/3/4";

    // APFS签名
    if (memcmp(buffer + 32, "NXSB", 4) == 0) return "APFS";

    // Btrfs签名
    if (memcmp(buffer + 65600, "_BHRfS_M", 8) == 0) return "Btrfs";

    return "RAW";
}