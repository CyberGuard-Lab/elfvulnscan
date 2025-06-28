// src/UnsafeDetector.cpp
#include "UnsafeDetector.h"
#include "Demangler.h"
#include <regex>

std::vector<UnsafeDetector::Finding>
UnsafeDetector::detect(const std::vector<Function>& funcs) const {
    std::vector<Finding> out;
    Demangler dem;
    std::regex targetPat(R"(<([^>]+)>)");
    for (auto& f : funcs) {
        std::string demName = dem.demangle(f.mangledName);
        for (auto& ins : f.insns) {
            if (ins.mnemonic != "call" && ins.mnemonic != "callq") continue;
            for (auto& bad : unsafeList) {
                if (ins.operands.find(bad) != std::string::npos) {
                    std::smatch m;
                    std::string tgt = ins.operands;
                    if (std::regex_search(ins.operands, m, targetPat)) {
                        tgt = dem.demangle(m[1].str());
                    }
                    out.push_back({demName, f.startAddress,
                                   ins.address, ins.mnemonic, tgt});
                    break;
                }
            }
        }
    }
    return out;
}
