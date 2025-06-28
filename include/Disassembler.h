// include/Disassembler.h
#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <string>
#include <vector>
#include <map>
#include <algorithm>

struct Instruction {
    std::string address;
    std::string mnemonic;
    std::string operands;
};

struct Function {
    std::string mangledName;    // Original name from objdump
    std::string demangledName;  // Cleaned/demangled name
    std::string startAddress;
    std::vector<Instruction> insns;
};

class Disassembler {
public:
    // Disassemble binary and collect functions with improved name resolution
    std::vector<Function> parse(const std::string& binaryPath) const;
    
private:
    std::string runCommand(const std::string& cmd) const;
    std::string cleanFunctionName(const std::string& rawName) const;
};

#endif // DISASSEMBLER_H