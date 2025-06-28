#ifndef COMMAND_INJECTION_DETECTOR_H
#define COMMAND_INJECTION_DETECTOR_H

#include "Disassembler.h"
#include <vector>
#include <string>

class CommandInjectionDetector {
public:
    struct Finding {
        std::string funcName;    // demangled function name
        std::string instrAddr;   // address of the instruction
        std::string target;      // target function name (e.g., system, popen)
        std::string detail;      // detail about the finding
    };

    std::vector<Finding> detect(const std::vector<Function>& funcs) const;

private:
    const std::vector<std::string> execList = {
        "system", "popen",
        "execl", "execle", "execlp",
        "execv", "execve", "execvp", "execvpe"
    };
};

#endif // COMMAND_INJECTION_DETECTOR_H
