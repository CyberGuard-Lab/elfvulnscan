// src/main.cpp
#include <iostream>
#include "Disassembler.h"
#include "Demangler.h"
#include "UnsafeDetector.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }
    std::string bin = argv[1];
    Disassembler dis;
    auto funcs = dis.parse(bin);
    UnsafeDetector det;
    auto findings = det.detect(funcs);
    for (auto& f : findings) {
        std::cout << "[!] Potential overflow in '" << f.funcName << "':\n";
        std::cout << "    • Function start : 0x" << f.funcStart << "\n";
        std::cout << "    • Instr @        : 0x" << f.instrAddr << "\n";
        std::cout << "    • Calls unsafe   : " << f.mnemonic
                  << " <" << f.target << ">\n\n";
    }
    return 0;
}
