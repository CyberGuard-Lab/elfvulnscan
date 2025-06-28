// src/HeapOverflowDetector.cpp
#include "HeapOverflowDetector.h"
#include "Disassembler.h"
#include "Demangler.h"
#include <cstdint>
#include <regex>
#include <unordered_map>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

using namespace std;

vector<HeapOverflowDetector::Finding> HeapOverflowDetector::detect(const vector<Function>& funcs) const {
    vector<Finding> findings;
    Demangler dem;
    regex immRegex(R"(0x[0-9A-Fa-f]+|(\d+))");

    for (const auto& f : funcs) {
        string funcName = dem.demangle(f.mangledName);
        if (funcName == f.mangledName || funcName == ".text") funcName = "";

        unordered_map<string, pair<uint64_t, string>> allocations;

        // Track heap allocations
        for (size_t i = 0; i + 1 < f.insns.size(); ++i) {
            const auto& ins = f.insns[i];
            const auto& next = f.insns[i + 1];
            smatch m;
            uint64_t size = 0;

            if ((next.mnemonic == "call" || next.mnemonic == "callq") && ins.mnemonic == "mov") {
                if (next.operands.find("malloc") != string::npos && regex_search(ins.operands, m, immRegex)) {
                    size = stoull(m.str(), nullptr, 0);
                } else if (next.operands.find("calloc") != string::npos && i + 2 < f.insns.size()) {
                    smatch m1, m2;
                    if (regex_search(f.insns[i].operands, m1, immRegex) &&
                        regex_search(f.insns[i + 1].operands, m2, immRegex)) {
                        size = stoull(m1.str(), nullptr, 0) * stoull(m2.str(), nullptr, 0);
                    }
                }

                if (size > 0) {
                    allocations["RAX"] = { size, next.address };
                }
            }
        }

        // Detect overflows on heap
        for (const auto& ins : f.insns) {
            string addr;
            stringstream ss;
            ss << "0x" << setfill('0') << setw(12) << hex << stoull(ins.address, nullptr, 16);
            addr = ss.str();

            if (ins.mnemonic == "call" || ins.mnemonic == "callq") {
                for (const auto& fn : { "memcpy", "memmove", "strcpy", "strncpy" }) {
                    if (ins.operands.find(fn) != string::npos) {
                        smatch m;
                        if (regex_search(ins.operands, m, immRegex)) {
                            uint64_t copySize = stoull(m.str(), nullptr, 0);
                            auto it = allocations.find("RAX");
                            uint64_t allocSize = (it != allocations.end()) ? it->second.first : 0;
                            string allocAddr = (it != allocations.end()) ? it->second.second : "unknown";

                            if (copySize > allocSize) {
                                string detail = string(fn) + " at " + addr +
                                    " copies " + to_string(copySize) +
                                    " bytes into buffer of size " + to_string(allocSize);
                                findings.push_back({ funcName, addr, detail });
                            }
                        }
                        break;
                    }
                }
            } else if (ins.mnemonic == "rep") {
                if (ins.operands.find("stosb") != string::npos || ins.operands.find("movsb") != string::npos) {
                    string detail = string("repeat string operation at ") + addr +
                        " may overflow heap buffer allocated at " +
                        (allocations.count("RAX") ? allocations["RAX"].second : string("unknown"));
                    findings.push_back({ funcName, addr, detail });
                }
            }
        }
    }

    return findings;
}