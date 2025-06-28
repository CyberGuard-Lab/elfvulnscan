// include/UnsafeDetector.h
#ifndef UNSAFE_DETECTOR_H
#define UNSAFE_DETECTOR_H

#include "Disassembler.h"
#include <vector>
#include <string>
#include <map>

class UnsafeDetector {
public:
    struct Finding {
        std::string funcName;
        std::string funcStart;
        std::string instrAddr;
        std::string mnemonic;
        std::string target;
        std::string detail;       // Added detailed analysis
        std::string riskLevel;    // Added risk level (HIGH/MEDIUM/LOW)
    };

    std::vector<Finding> detect(const std::vector<Function>& funcs) const;

private:
    // Core unsafe function list - kept for backward compatibility
    const std::vector<std::string> unsafeList = {
    // HIGH RISK
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "scanf",

    // MEDIUM RISK
    "strncpy",
    "strncat",
    "snprintf",
    "memcpy",
    "memmove"
};


    // Helper methods for improved analysis
    std::string extractCalledFunction(const std::string& operands) const;
    void analyzeBufferContext(const Function& func, std::map<std::string, size_t>& bufferSizes) const;
    bool isLikelyVulnerable(const Function& func, const Instruction& ins, 
                           const std::string& funcName, 
                           const std::map<std::string, size_t>& bufferSizes) const;
    std::string generateDetailedAnalysis(const Function& func, const Instruction& ins,
                                        const std::string& funcName, const std::string& riskLevel,
                                        const std::map<std::string, size_t>& bufferSizes) const;
};

#endif // UNSAFE_DETECTOR_H