// include/Disassembler.h
#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <string>
#include <vector>

struct Instruction {
    std::string address;
    std::string mnemonic;
    std::string operands;
};

struct Function {
    std::string mangledName;
    std::string demangledName;
    std::string startAddress;
    std::vector<Instruction> insns;
};

class Disassembler {
public:
    // Disassemble binary and collect functions
    std::vector<Function> parse(const std::string& binaryPath) const;
private:
    std::string runCommand(const std::string& cmd) const;
};

#endif // DISASSEMBLER_H