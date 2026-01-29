# MusicUSBEncrypt - FAT32 U盘加密工具

## 概述

**MusicUSBEncrypt** 是一款基于Qt框架开发的Windows平台U盘加密软件（虽然称为加密有点欠妥），专门针对FAT32文件系统分区进行底层防复制保护。该软件通过修改文件系统引导扇区（Boot Sector）和FSInfo扇区的保留字节来实现驱动器防复制，无需创建额外的加密容器，保持FAT32的兼容性。

## 核心功能

### 1. 驱动器加密保护
- **快速加密**：直接修改分区表结构，秒级完成加密初始化
- **密码保护**：支持自定义密码，使用哈希算法存储验证
- **格式检测**：自动检测并仅支持标准FAT32格式分区

### 2. 驱动器管理
- **分区识别**：自动扫描并列出系统中所有可用的逻辑分区
- **安全弹出**：集成Windows驱动器安全移除功能
- **格式化支持**：支持将分区格式化为标准FAT32文件系统

### 3. 状态检测
- **加密识别**：自动检测驱动器当前的加密状态
- **格式验证**：验证分区是否为支持的FAT32原始格式

## 技术实现

### 加密机制

本软件采用**FAT32文件系统结构修改**方案，具体技术手段如下：

#### 1. Boot Sector 标记（引导扇区）
- **位置**：0x5A - 0x5D（BPB保留字节）
- **内容**：写入4字节特殊标记序列（`specialMarkBytes`）
- **媒体描述符**：偏移0x15处修改为加密专用标识（`encryptedMediaDescriptor`）

#### 2. FSInfo Sector 密码存储
- **位置**：0x04 - 0x1E3（FSInfo保留区域，共476字节）
- **存储内容**：用户密码的加密哈希值
- **加密算法**：通过`EnDecryptor`类实现，支持长度自适应加密

#### 3. 双重验证机制
- 第一层：特殊标记验证（Boot Sector 0x5A-0x5D）
- 第二层：媒体描述符验证（偏移0x15）
- 第三层：密码哈希验证（FSInfo Sector）

### 代码架构

#### 核心类结构
```cpp
class MusicUSBEncrypt : public QMainWindow
├── 加密状态检测
│   ├── isEncrypted()               // 综合检测加密状态
│   ├── detectSpecialMark()         // 检测引导扇区标记
│   ├── getMediaDescriptor()        // 检测媒体介质描述符
│   └── verifyPasswordMark()        // 验证密码哈希
├── 加密操作
│   ├── encryptDrive()              // 执行加密流程
│   ├── writeSpecialMark()          // 写入引导扇区标记
│   ├── writePasswordMark()         // 写入密码哈希
│   └── changeMediaDescriptor()     // 修改媒体介质描述符
├── 解密操作
│   ├── decryptDrive()              // 执行解密流程
│   ├── removeSpecialMark()         // 清除引导扇区标记
│   ├── removePasswordMark()        // 清除密码哈希
│   └── changeMediaDescriptor()     // 恢复标准硬盘标识
└── UI交互
    ├── encryptPartition()          // 加密按钮槽函数
    ├── decryptPartition()          // 解密按钮槽函数
    ├── formatPartition()           // 格式化功能
    ├── ejectDrive()                // 安全移除驱动器
    └── uiUpdateDriveList()         // 刷新驱动器列表

