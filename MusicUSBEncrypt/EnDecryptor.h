#pragma once
#include <sodium.h>
#include <string>
#include <stdexcept>

class EnDecryptor
{
	static bool initialized;

public:
	EnDecryptor() {
		initialize();
	}

	static bool initialize() {
		if (!initialized)
		{
			if (sodium_init() < 0)
				return false;
			initialized = true;
		}
		return true;
	}
	static bool isInitialized() {
		return initialized;
	}
	
	/**
	 * 哈希密码
	 * \return: Argon2id编码字符串（包含盐值、参数和哈希值）
	 * 格式: $argon2id$v=19$m=65536,t=3,p=4$...
	 */
	std::string hashPassword(const std::string& password) {
		// 使用sodium_malloc保护敏感内存
		char* hash_str = (char*)sodium_malloc(crypto_pwhash_STRBYTES);
		if (!hash_str)
			throw std::bad_alloc();
		// 使用HIGH_LEVEL参数（可根据硬件调整）
		// OPSLIMIT_INTERACTIVE: 3次迭代
		// MEMLIMIT_INTERACTIVE: 64MB内存
		if (crypto_pwhash_str(hash_str, password.c_str(), password.length(), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
		{
			sodium_free(hash_str);
			throw std::runtime_error("内存分配失败（可能需要减少MEMLIMIT）");
		}
		std::string result(hash_str);
		sodium_free(hash_str);  // 安全释放
		// 清除输入密码的内存（防御性编程）
		return result;
	}

	/**
	 * 验证密码
	 * 自动解析hash字符串中的盐值和参数
	 */
	bool verifyPassword(const std::string& password, const std::string& hash) {
		int result = crypto_pwhash_str_verify(hash.c_str(), password.c_str(), password.length());
		return result == 0;
	}

	/**
	 * 检查是否需要升级哈希参数（硬件升级后使用）
	 */
	bool needsRehash(const std::string& hash) {
		return crypto_pwhash_str_needs_rehash(hash.c_str(), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0;
	}

	/**
     * \brief 简单的异或加密，用于密码过长时的等长加密
	 */
	std::string xorEncrypt(std::string password) {
		for (size_t i = 0; i < password.size(); ++i)
			password[i] ^= (char)(i % 256);
		return password;
	}

	std::string lengthEqualEncryptPassword(const std::string& password) {
		return xorEncrypt(password);
    }

	bool verifyLengthEqualEncryptPassword(const std::string& password, const std::string& encrypted) {
		std::string encryptedNew = xorEncrypt(password);
		return encryptedNew == encrypted;
    }
};

inline bool EnDecryptor::initialized = false;
