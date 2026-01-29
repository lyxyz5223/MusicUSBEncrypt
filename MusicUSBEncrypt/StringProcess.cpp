#include "StringProcess.h"
#include <Windows.h>
std::string wstr2str_2UTF8(std::wstring text)
{
	CHAR* str;
	int Tsize = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, 0, 0, 0, 0);
	str = new CHAR[Tsize];
	WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, str, Tsize, 0, 0);
	std::string str1 = str;
	delete[]str;
	return str1;
}
std::string wstr2str_2ANSI(std::wstring text)
{
	CHAR* str;
	int Tsize = WideCharToMultiByte(CP_ACP, 0, text.c_str(), -1, 0, 0, 0, 0);
	str = new CHAR[Tsize];
	WideCharToMultiByte(CP_ACP, 0, text.c_str(), -1, str, Tsize, 0, 0);
	std::string str1 = str;
	delete[]str;
	return str1;
}

std::wstring str2wstr_2UTF8(std::string text)
{
	WCHAR* str;
	int Tsize = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, 0, 0);
	str = new WCHAR[Tsize];
	MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, str, Tsize);
	std::wstring str1 = str;
	delete[]str;
	return str1;
}

std::wstring str2wstr_2ANSI(std::string text)
{
	WCHAR* str;
	int Tsize = MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, 0, 0);
	str = new WCHAR[Tsize];
	MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, str, Tsize);
	std::wstring str1 = str;
	delete[]str;
	return str1;

}

std::string UTF8ToANSI(std::string utf8Text)
{
	WCHAR* wstr;//中间量
	CHAR* str;//转换后的
	int Tsize = MultiByteToWideChar(CP_UTF8, 0, utf8Text.c_str(), -1, 0, 0);
	wstr = new WCHAR[Tsize];
	MultiByteToWideChar(CP_UTF8, 0, utf8Text.c_str(), -1, wstr, Tsize);
	Tsize = WideCharToMultiByte(CP_ACP, 0, wstr, -1, 0, 0, 0, 0);
	str = new CHAR[Tsize];
	WideCharToMultiByte(CP_ACP, 0, wstr, -1, str, Tsize, 0, 0);
	std::string wstr1 = str;
	delete[]str;
	delete[]wstr;
	return wstr1;
}
std::string ANSIToUTF8(std::string ansiText)
{
	WCHAR* wstr;//中间量
	CHAR* str;//转换后的
	int Tsize = MultiByteToWideChar(CP_ACP, 0, ansiText.c_str(), -1, 0, 0);
	wstr = new WCHAR[Tsize];
	MultiByteToWideChar(CP_ACP, 0, ansiText.c_str(), -1, wstr, Tsize);
	Tsize = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, 0, 0, 0, 0);
	str = new CHAR[Tsize];
	WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, Tsize, 0, 0);
	std::string wstr1 = str;
	delete[]str;
	delete[]wstr;
	return wstr1;
}

std::wstring ANSIToUTF8(std::wstring ansiText)
{
	CHAR* str;//中间量
	WCHAR* wstr;//转换后的
	int Tsize = WideCharToMultiByte(CP_ACP, 0, ansiText.c_str(), -1, 0, 0, 0, 0);
	str = new CHAR[Tsize];
	WideCharToMultiByte(CP_ACP, 0, ansiText.c_str(), -1, str, Tsize, 0, 0);
	Tsize = MultiByteToWideChar(CP_UTF8, 0, str, -1, 0, 0);
	wstr = new WCHAR[Tsize];
	MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, Tsize);
	std::wstring wstr1 = wstr;
	delete[]str;
	delete[]wstr;
	return wstr1;
}
std::wstring UTF8ToANSI(std::wstring utf8Text)
{
	CHAR* str;//中间量
	WCHAR* wstr;//转换后的
	int Tsize = WideCharToMultiByte(CP_UTF8, 0, utf8Text.c_str(), -1, 0, 0, 0, 0);
	str = new CHAR[Tsize];
	WideCharToMultiByte(CP_UTF8, 0, utf8Text.c_str(), -1, str, Tsize, 0, 0);
	Tsize = MultiByteToWideChar(CP_ACP, 0, str, -1, 0, 0);
	wstr = new WCHAR[Tsize];
	MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, Tsize);
	std::wstring wstr1 = wstr;
	delete[]str;
	delete[]wstr;
	return wstr1;
}

std::wstring boolToWString(bool Bool)
{
	return (Bool ? L"true" : L"false");
}

std::string boolToString(bool Bool)
{
	return (Bool ? "true" : "false");
}

