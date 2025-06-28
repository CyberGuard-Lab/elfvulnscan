// src/UnsafeDetector.cpp
#include "UnsafeDetector.h"
#include "Demangler.h"
#include <regex>
#include <set>
#include <algorithm>

std::vector<UnsafeDetector::Finding>
UnsafeDetector::detect(const std::vector<Function>& funcs) const {
    std::vector<Finding> out;
    Demangler dem;
    
    // Safe functions that are generally okay to use
    std::set<std::string> safeFunctions = {
        "puts", "printf", "fprintf", "fwrite", "write",
        "strlen", "strcmp", "strncmp", "memcmp", "malloc", "free",
        "fopen", "fclose", "exit", "_exit", "abort",
        "getpid", "getuid", "getgid", "time", "clock"
    };
    
    // High-risk functions that are more likely to be problematic
    std::set<std::string> highRiskFunctions = {
        "gets", "strcpy", "strcat", "sprintf", "vsprintf",
        "scanf", "sscanf", "fscanf"
    };
    
    // Medium-risk functions that need context analysis
    std::set<std::string> mediumRiskFunctions = {
        "strncpy", "strncat", "snprintf", "vsnprintf",
        "memcpy", "memmove", "fgets", "getchar"
    };
    
    std::regex targetPat(R"(<([^>]+)>)");
    std::regex addressPat(R"(0x[0-9a-fA-F]+)");
    
    for (const auto& f : funcs) {
        std::string demName = dem.demangle(f.mangledName);
        
        // Try to get a better function name if demangling failed
        if (demName == f.mangledName || demName == ".text" || demName.empty()) {
            // Extract function name from objdump output patterns
            if (f.mangledName.find("@plt") != std::string::npos) {
                continue; // Skip PLT entries
            }
            
            // Use the mangled name but clean it up
            demName = f.mangledName;
            
            // Remove common prefixes/suffixes
            if (demName.find("_Z") == 0) {
                // This is a mangled C++ name, keep trying to demangle
                demName = dem.demangle(f.mangledName);
            }
            
            // If still generic, skip or use start address as identifier
            if (demName == ".text" || demName.empty()) {
                demName = "func_" + f.startAddress;
            }
        }
        
        // Context analysis: look for buffer size patterns
        std::map<std::string, size_t> bufferSizes;
        analyzeBufferContext(f, bufferSizes);
        
        for (const auto& ins : f.insns) {
            if (ins.mnemonic != "call" && ins.mnemonic != "callq") 
                continue;
                
            std::string calledFunction = extractCalledFunction(ins.operands);
            if (calledFunction.empty()) continue;
            
            // Skip if it's a safe function
            if (safeFunctions.count(calledFunction)) continue;
            
            // Check if it's in our unsafe list
            bool isUnsafe = false;
            std::string riskLevel;
            
            if (highRiskFunctions.count(calledFunction)) {
                isUnsafe = true;
                riskLevel = "HIGH";
            } else if (mediumRiskFunctions.count(calledFunction)) {
                // For medium risk, do additional context checking
                if (isLikelyVulnerable(f, ins, calledFunction, bufferSizes)) {
                    isUnsafe = true;
                    riskLevel = "MEDIUM";
                }
            } else {
                // Check against full unsafe list for remaining functions
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
                out.push_back({demName, f.startAddress, ins.address, ins.mnemonic, calledFunction, detail, riskLevel});
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
    
    // Try to extract direct function names
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
        
        // Look for stack allocation patterns
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
        
        // Look for buffer size constants being loaded
        if (ins.mnemonic == "mov" && (ins.operands.find("%rdx") != std::string::npos || 
                                     ins.operands.find("%rcx") != std::string::npos)) {
            std::smatch m;
            if (std::regex_search(ins.operands, m, sizePat)) {
                size_t size = std::stoull(m[1].str());
                if (size < 10000) { // Reasonable buffer size
                    bufferSizes["arg"] = size;
                }
            }
        }
    }
}

bool UnsafeDetector::isLikelyVulnerable(const Function& func, const Instruction& ins, 
                                       const std::string& funcName, 
                                       const std::map<std::string, size_t>& bufferSizes) const {
    
    // High-risk functions are always considered vulnerable
    if (funcName == "gets" || funcName == "scanf" || funcName == "sprintf") {
        return true;
    }
    
    // For functions like strncpy, snprintf - check if size parameter looks reasonable
    if (funcName == "strncpy" || funcName == "strncat" || funcName == "snprintf") {
        // Look for size argument in preceding instructions
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
                    // If size is very large or suspiciously round number, might be vulnerable
                    if (argSize > 1000 || argSize % 100 == 0) {
                        return true;
                    }
                }
            }
        }
        return false; // If we found reasonable size checking, probably okay
    }
    
    // For memcpy/memmove, always flag if no clear size bounds
    if (funcName == "memcpy" || funcName == "memmove") {
        return true; // These need careful analysis of size parameters
    }
    
    // For fgets, check if buffer size argument is reasonable
    if (funcName == "fgets") {
        return false; // fgets is generally safer as it takes buffer size
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
    
    // Add buffer context if available
    if (!bufferSizes.empty()) {
        detail += "";
    }
    
    return detail;
}