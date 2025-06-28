#include "CommandInjectionDetector.h"
#include "Demangler.h"
#include <regex>
#include <sstream>
#include <iomanip>

std::vector<CommandInjectionDetector::Finding>
CommandInjectionDetector::detect(const std::vector<Function>& funcs) const {
    std::vector<Finding> out;
    Demangler dem;

    for (const auto& f : funcs) {
        std::string funcName = dem.demangle(f.mangledName);
        if (funcName == f.mangledName || funcName == ".text") {
            funcName.clear();  // Bỏ nếu không rõ ràng
        }

        for (const auto& ins : f.insns) {
            if (ins.mnemonic != "call" && ins.mnemonic != "callq")
                continue;

            for (const auto& fn : execList) {
                if (ins.operands.find(fn) != std::string::npos) {
                    std::stringstream addrStream;
                    addrStream << "0x" << std::setfill('0') << std::setw(12)
                               << std::hex << std::stoull(ins.address, nullptr, 16);

                    std::string detail = "Call to `" + std::string(fn) + "` at " +
                                         addrStream.str() +
                                         " can lead to command injection risks.";

                    out.push_back({ funcName, addrStream.str(), fn, detail });
                    break;
                }
            }
        }
    }

    return out;
}
