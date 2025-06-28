#include "UnsafeDetector.h"
#include "Demangler.h"
#include <regex>
#include <set>
#include <algorithm>
#include <sstream>
#include <cstdint>
#include <iomanip>

std::vector<UnsafeDetector::Finding>
UnsafeDetector::detect(const std::vector<Function>& funcs) const {
    std::vector<Finding> out;
    Demangler dem;

    std::set<std::string> safeFunctions = {
        "puts", "printf", "fprintf", "fwrite", "write",
        "strlen", "strcmp", "strncmp", "memcmp", "malloc", "free",
        "fopen", "fclose", "exit", "_exit", "abort",
        "getpid", "getuid", "getgid", "time", "clock"
    };

    std::set<std::string> highRiskFunctions = {
        "gets", "strcpy", "strcat", "sprintf", "vsprintf",
        "scanf", "sscanf", "fscanf"
    };

    std::set<std::string> mediumRiskFunctions = {
        "strncpy", "strncat", "snprintf", "vsnprintf",
        "memcpy", "memmove", "fgets", "getchar"
    };

    for (const auto& f : funcs) {
        std::string demName = dem.demangle(f.mangledName);

        // Xử lý fallback: nếu demangle không thành công thì bỏ qua tên hàm
        bool isInvalidName = demName.empty() || demName == f.mangledName || demName == ".text";
        bool isPltEntry = f.mangledName.find("@plt") != std::string::npos;
        if (isInvalidName) {
            if (isPltEntry) continue;
            demName.clear();
        }

        std::map<std::string, size_t> bufferSizes;
        analyzeBufferContext(f, bufferSizes);

        for (const auto& ins : f.insns) {
            if (ins.mnemonic != "call" && ins.mnemonic != "callq")
                continue;

            std::string calledFunction = extractCalledFunction(ins.operands);
            if (calledFunction.empty()) continue;
            if (safeFunctions.count(calledFunction)) continue;

            bool isUnsafe = false;
            std::string riskLevel;

            if (highRiskFunctions.count(calledFunction)) {
                isUnsafe = true;
                riskLevel = "HIGH";
            } else if (mediumRiskFunctions.count(calledFunction)) {
                if (isLikelyVulnerable(f, ins, calledFunction, bufferSizes)) {
                    isUnsafe = true;
                    riskLevel = "MEDIUM";
                }
            } else {
                for (const auto& unsafe : unsafeList) {
                    if (calledFunction.find(unsafe) != std::string::npos) {
                        if (highRiskFunctions.count(unsafe)) {
                            isUnsafe = true;
                            riskLevel = "HIGH";
                        } else if (mediumRiskFunctions.count(unsafe)) {
                            if (isLikelyVulnerable(f, ins, unsafe, bufferSizes)) {
                                isUnsafe = true;
                                riskLevel = "MEDIUM";
                            }
                        } else {
                            if (isLikelyVulnerable(f, ins, unsafe, bufferSizes)) {
                                isUnsafe = true;
                                riskLevel = "LOW";
                            }
                        }
                        calledFunction = unsafe;
                        break;
                    }
                }
            }

            if (isUnsafe) {
                std::string detail = generateDetailedAnalysis(f, ins, calledFunction, riskLevel, bufferSizes);

                std::stringstream actualAddr;
                actualAddr << "0x" << std::setfill('0') << std::setw(12)
                           << std::hex << std::stoull(ins.address, nullptr, 16);

                Finding finding;
                finding.funcName = demName;
                finding.funcStart = f.startAddress;
                finding.instrAddr = actualAddr.str();
                finding.mnemonic = ins.mnemonic;
                finding.target = calledFunction;
                finding.detail = detail;
                finding.riskLevel = riskLevel;

                out.push_back(finding);
            }
        }
    }

    return out;
}

std::string UnsafeDetector::extractCalledFunction(const std::string& operands) const {
    std::regex targetPat(R"(<([^>@]+)(?:@plt)?>)");
    std::smatch m;

    if (std::regex_search(operands, m, targetPat)) {
        return m[1].str();
    }

    std::regex directPat(R"((\w+)@plt)");
    if (std::regex_search(operands, m, directPat)) {
        return m[1].str();
    }

    return "";
}

void UnsafeDetector::analyzeBufferContext(const Function& func, std::map<std::string, size_t>& bufferSizes) const {
    std::regex immediatePat(R"(\$0x([0-9a-fA-F]+))");
    std::regex sizePat(R"(\$(\d+))");

    for (size_t i = 0; i < func.insns.size(); ++i) {
        const auto& ins = func.insns[i];

        if (ins.mnemonic == "sub" && ins.operands.find("%rsp") != std::string::npos) {
            std::smatch m;
            if (std::regex_search(ins.operands, m, immediatePat)) {
                size_t stackSize = std::stoull(m[1].str(), nullptr, 16);
                bufferSizes["stack"] = stackSize;
            } else if (std::regex_search(ins.operands, m, sizePat)) {
                size_t stackSize = std::stoull(m[1].str());
                bufferSizes["stack"] = stackSize;
            }
        }

        if (ins.mnemonic == "mov" && (ins.operands.find("%rdx") != std::string::npos || 
                                      ins.operands.find("%rcx") != std::string::npos)) {
            std::smatch m;
            if (std::regex_search(ins.operands, m, sizePat)) {
                size_t size = std::stoull(m[1].str());
                if (size < 10000) {
                    bufferSizes["arg"] = size;
                }
            }
        }
    }
}

bool UnsafeDetector::isLikelyVulnerable(const Function& func, const Instruction& ins,
                                       const std::string& funcName,
                                       const std::map<std::string, size_t>& bufferSizes) const {
    if (funcName == "gets" || funcName == "scanf" || funcName == "sprintf") {
        return true;
    }

    if (funcName == "strncpy" || funcName == "strncat" || funcName == "snprintf") {
        for (int i = static_cast<int>(std::find_if(func.insns.begin(), func.insns.end(),
            [&ins](const Instruction& inst) { return inst.address == ins.address; }) - func.insns.begin()) - 1;
             i >= 0 && i >= static_cast<int>(func.insns.size()) - 5; i--) {

            const auto& prevIns = func.insns[i];
            if (prevIns.mnemonic == "mov" &&
                (prevIns.operands.find("%rdx") != std::string::npos ||
                 prevIns.operands.find("%rcx") != std::string::npos)) {

                std::regex sizePat(R"(\$(\d+))");
                std::smatch m;
                if (std::regex_search(prevIns.operands, m, sizePat)) {
                    size_t argSize = std::stoull(m[1].str());
                    if (argSize > 1000 || argSize % 100 == 0) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    if (funcName == "memcpy" || funcName == "memmove") {
        return true;
    }

    if (funcName == "fgets") {
        return false;
    }

    return false;
}

std::string UnsafeDetector::generateDetailedAnalysis(const Function& func, const Instruction& ins,
                                                    const std::string& funcName, const std::string& riskLevel,
                                                    const std::map<std::string, size_t>& bufferSizes) const {
    std::string detail = "Risk: " + riskLevel + " - ";

    if (funcName == "gets") {
        detail += "gets() doesn't check buffer bounds";
    } else if (funcName == "strcpy") {
        detail += "strcpy() doesn't check destination size";
    } else if (funcName == "strcat") {
        detail += "strcat() doesn't check destination size";
    } else if (funcName == "sprintf") {
        detail += "sprintf() doesn't check buffer size";
    } else if (funcName == "scanf" || funcName == "sscanf" || funcName == "fscanf") {
        detail += "scanf family can overflow buffers";
    } else if (funcName == "memcpy" || funcName == "memmove") {
        detail += "Memory copy without bounds checking";
    } else {
        detail += "Potentially unsafe function call";
    }

    return detail;
}
