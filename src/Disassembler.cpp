// src/Disassembler.cpp
#include "Disassembler.h"
#include <array>
#include <memory>
#include <cstdio>
#include <sstream>
#include <regex>

// Custom deleter to avoid attribute warning
struct FileCloser {
    void operator()(FILE* f) const noexcept { if (f) pclose(f); }
};

std::string Disassembler::runCommand(const std::string& cmd) const {
    std::array<char, 256> buf;
    std::string out;
    std::unique_ptr<FILE, FileCloser> pipe(popen(cmd.c_str(), "r"), FileCloser{});
    if (!pipe) return out;
    while (fgets(buf.data(), buf.size(), pipe.get())) out += buf.data();
    return out;
}

std::vector<Function> Disassembler::parse(const std::string& binaryPath) const {
    std::string dump = runCommand("objdump -d " + binaryPath);
    std::istringstream iss(dump);
    std::regex funcPat(R"(^([0-9a-f]+) <([^>]+)>:)");
    // Updated regex to match hex bytes and allow spaces/tabs
    std::regex insnPat(R"(^\s*([0-9a-fA-F]+):\s*([\da-fA-F]{2}(?:\s+[\da-fA-F]{2})*)\s+(\w+)\s+(.+)$)");
    std::vector<Function> funcs;
    Function* current = nullptr;
    std::string line;
    while (std::getline(iss, line)) {
        std::smatch m;
        if (std::regex_search(line, m, funcPat)) {
            funcs.push_back({m[2].str(), "", m[1].str(), {}});
            current = &funcs.back();
            continue;
        }
        if (!current) continue;
        if (std::regex_search(line, m, insnPat)) {
            // m[1]=address, m[2]=hex bytes, m[3]=mnemonic, m[4]=operands
            current->insns.push_back({m[1].str(), m[3].str(), m[4].str()});
        }
    }
    return funcs;
}