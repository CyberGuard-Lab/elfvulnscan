// src/main.cpp
#include <iostream>
#include "Disassembler.h"
#include "Demangler.h"
#include "UnsafeDetector.h"
#include "HeapOverflowDetector.h"
#include "CommandInjectionDetector.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }
    std::string bin = argv[1];
    Disassembler dis;
    auto funcs = dis.parse(bin);

    // Detect unsafe calls (stack-based overflows)
    UnsafeDetector unsafeDet;
    auto unsafeFindings = unsafeDet.detect(funcs);
    for (const auto& f : unsafeFindings) {
        std::cout << "[!] Potential unsafe call (stack-based overflows) in '" << f.funcName << "':\n";
        std::cout << "    • Function start : 0x" << f.funcStart << "\n";
        std::cout << "    • Instr @        : 0x" << f.instrAddr << "\n";
        std::cout << "    • Calls unsafe   : " << f.mnemonic
                  << " <" << f.target << ">\n\n";
    }

    // Detect heap-based overflows
    HeapOverflowDetector heapDet;
    auto heapFindings = heapDet.detect(funcs);
    for (const auto& h : heapFindings) {
        std::cout << "[!] Potential heap-based overflow in '" << h.funcName << "':\n";
        std::cout << "    • Instr @        : 0x" << h.instrAddr << "\n";
        std::cout << "    • Detail         : " << h.detail << "\n\n";
    }

    // Detect command-injection risks
    CommandInjectionDetector cmdDet;
    auto cmdFindings = cmdDet.detect(funcs);
    for (const auto& c : cmdFindings) {
        std::cout << "[!] Potential command injection in '" 
                  << c.funcName << "':\n";
        std::cout << "    • Instr @        : 0x" << c.instrAddr << "\n";
        std::cout << "    • Call to        : " << c.target << "\n";
        std::cout << "    • Detail         : " << c.detail << "\n\n";
    }

    return 0;
}
