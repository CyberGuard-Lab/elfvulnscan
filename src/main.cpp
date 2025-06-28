// src/main.cpp
#include <iostream>
#include <iomanip>
#include "Disassembler.h"
#include "Demangler.h"
#include "UnsafeDetector.h"
#include "HeapOverflowDetector.h"
#include "CommandInjectionDetector.h"

void printSeparator(const std::string& title) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << " " << title << "\n";
    std::cout << std::string(60, '=') << "\n";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }
    
    std::string bin = argv[1];
    std::cout << "Analyzing binary: " << bin << "\n";
    
    Disassembler dis;
    auto funcs = dis.parse(bin);
    
    std::cout << "Found " << funcs.size() << " functions to analyze.\n";

    // Detect unsafe calls (stack-based overflows) with improved filtering
    printSeparator("UNSAFE FUNCTION CALLS ANALYSIS");
    UnsafeDetector unsafeDet;
    auto unsafeFindings = unsafeDet.detect(funcs);
    
    if (unsafeFindings.empty()) {
        std::cout << "✓ No unsafe function calls detected.\n";
    } else {
        // Group by risk level
        std::map<std::string, std::vector<UnsafeDetector::Finding>> groupedFindings;
        for (const auto& f : unsafeFindings) {
            groupedFindings[f.riskLevel].push_back(f);
        }
        
        // Display HIGH risk first
        for (const auto& riskGroup : {"HIGH", "MEDIUM", "LOW"}) {
            if (groupedFindings.count(riskGroup) && !groupedFindings[riskGroup].empty()) {
                std::cout << "\n[" << riskGroup << " RISK] Found " 
                         << groupedFindings[riskGroup].size() << " issues:\n";
                std::cout << std::string(50, '-') << "\n";
                
                for (const auto& f : groupedFindings[riskGroup]) {
                    if (!f.funcName.empty()) {
                        std::cout << "   Function: " << f.funcName << "\n";
                    }
                    std::cout << "   Address  : 0x" << f.instrAddr << "\n";
                    std::cout << "   Calls    : " << f.target << "\n";
                    std::cout << "   Analysis : " << f.detail << "\n\n";
                }
            }
        }
    }

    // Detect heap-based overflows
    printSeparator("HEAP OVERFLOW ANALYSIS");
    HeapOverflowDetector heapDet;
    auto heapFindings = heapDet.detect(funcs);
    
    if (heapFindings.empty()) {
        std::cout << "✓ No heap overflow vulnerabilities detected.\n";
    } else {
        for (const auto& h : heapFindings) {
            if (h.funcName != ".text") {
                std::cout << "   Potential heap overflow in '" << h.funcName << "':\n";
            }
            std::cout << "   Address: 0x" << h.instrAddr << "\n";
            std::cout << "   Detail : " << h.detail << "\n\n";
        }
    }

    // Detect command-injection risks
    printSeparator("COMMAND INJECTION ANALYSIS");
    CommandInjectionDetector cmdDet;
    auto cmdFindings = cmdDet.detect(funcs);
    
    if (cmdFindings.empty()) {
        std::cout << "✓ No command injection vulnerabilities detected.\n";
    } else {
        for (const auto& c : cmdFindings) {
            if (c.funcName != ".text"){
                std::cout << "   Potential command injection in '" << c.funcName << "':\n";
            }
            std::cout << "   Address: 0x" << c.instrAddr << "\n";
            std::cout << "   Calls  : " << c.target << "\n";
            std::cout << "   Detail : " << c.detail << "\n\n";
        }
    }

    // Summary
    printSeparator("SUMMARY");
    int totalIssues = unsafeFindings.size() + heapFindings.size() + cmdFindings.size();
    
    std::cout << "Total issues found: " << totalIssues << "\n";
    std::cout << "├─ Unsafe function calls: " << unsafeFindings.size() << "\n";
    std::cout << "├─ Heap overflows       : " << heapFindings.size() << "\n";
    std::cout << "└─ Command injections   : " << cmdFindings.size() << "\n";
    
    if (totalIssues == 0) {
        std::cout << "\nBinary appears to be free of common vulnerability patterns.\n";
    } else {
        std::cout << "\nReview flagged issues carefully - some may be false positives.\n";
        std::cout << "   Focus on HIGH risk findings first.\n";
    }

    return 0;
}