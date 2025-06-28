#include "CommandInjectionDetector.h"
#include "Demangler.h"
#include <regex>

std::vector<CommandInjectionDetector::Finding>
CommandInjectionDetector::detect(const std::vector<Function>& funcs) const {
    std::vector<Finding> out;
    Demangler dem;

    for (const auto& f : funcs) {
        std::string demName = dem.demangle(f.mangledName);
        for (const auto& ins : f.insns) {
            if (ins.mnemonic != "call" && ins.mnemonic != "callq")
                continue;
            for (const auto& fn : execList) {
                if (ins.operands.find(fn) != std::string::npos) {
                    std::string detail = 
                        "Call to `" + fn + "` at 0x" + ins.address + "can lead to command injection risks.";
                    out.push_back({demName, ins.address, fn, detail});
                    break;
                }
            }
        }
    }
    return out;
}
