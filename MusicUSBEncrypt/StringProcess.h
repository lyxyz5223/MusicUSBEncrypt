#pragma once
#include <string>

std::string wstr2str_2UTF8(std::wstring text);
std::string wstr2str_2ANSI(std::wstring text);
std::wstring str2wstr_2UTF8(std::string text);
std::wstring str2wstr_2ANSI(std::string text);
std::string UTF8ToANSI(std::string utf8Text);
std::string ANSIToUTF8(std::string ansiText);
std::wstring ANSIToUTF8(std::wstring ansiText);
std::wstring UTF8ToANSI(std::wstring utf8Text);

std::wstring boolToWString(bool Bool);
std::string boolToString(bool Bool);