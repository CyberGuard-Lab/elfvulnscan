// include/UnsafeDetector.h
#ifndef UNSAFE_DETECTOR_H
#define UNSAFE_DETECTOR_H

#include "Disassembler.h"
#include <vector>
#include <string>

class UnsafeDetector {
public:
    struct Finding {
        std::string funcName;
        std::string funcStart;
        std::string instrAddr;
        std::string mnemonic;
        std::string target;
    };

    std::vector<Finding> detect(const std::vector<Function>& funcs) const;

private:
    const std::vector<std::string> unsafeList = {
        "strcpy","strcat","sprintf","vsprintf",
        "gets","scanf","memcpy","memmove",
        "strncpy","strncat","snprintf","vsnprintf",
        "sscanf","fscanf","fgets","getchar",
        "getc","ungetc","puts","fputs",
        "wcscpy","wcscat","wcsncat","wcsncpy",
        "wmemcpy","wmemmove","swprintf","vswprintf",
        "readlink","getwd","realpath","syslog"
    };
};

#endif // UNSAFE_DETECTOR_H