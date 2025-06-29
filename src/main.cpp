#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <string>
#include <map>

#include "Disassembler.h"
#include "Demangler.h"
#include "UnsafeDetector.h"
#include "HeapOverflowDetector.h"
#include "CommandInjectionDetector.h"

void printSeparator(std::ostringstream& oss, const std::string& title) {
    oss << "\n" << title << "\n";
    oss << std::string(60, '=') << "\n";
}

void sendFindingsToGemini(const std::string& findingsText) {
    std::ofstream out("tmp_findings.txt");
    out << findingsText;
    out.close();
    std::system("python3 gemini_client.py \"$(cat tmp_findings.txt)\"");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    std::ostringstream oss;

    std::string bin = argv[1];
    oss << "Analyzing binary: " << bin << "\n";

    Disassembler dis;
    auto funcs = dis.parse(bin);
    oss << "Found " << funcs.size() << " functions to analyze.\n";

    printSeparator(oss, "BUFFER OVERFLOW ANALYSIS");
    UnsafeDetector unsafeDet;
    auto unsafeFindings = unsafeDet.detect(funcs);

    if (unsafeFindings.empty()) {
        oss << "✓ No unsafe function calls detected.\n";
    } else {
        std::map<std::string, std::vector<UnsafeDetector::Finding>> groupedFindings;
        for (const auto& f : unsafeFindings)
            groupedFindings[f.riskLevel].push_back(f);

        for (const auto& riskGroup : {"HIGH", "MEDIUM", "LOW"}) {
            if (!groupedFindings[riskGroup].empty()) {
                oss << "\n[" << riskGroup << " RISK] Found "
                    << groupedFindings[riskGroup].size() << " issues:\n";
                oss << std::string(50, '-') << "\n";

                std::map<std::string, std::vector<std::string>> groupedByFunc;
                std::map<std::string, std::string> funcAnalysis;

                for (const auto& f : groupedFindings[riskGroup]) {
                    std::string key = f.target + "|" + f.detail;
                    groupedByFunc[key].push_back(f.instrAddr);
                    funcAnalysis[key] = f.detail;
                }

                for (const auto& [key, addrs] : groupedByFunc) {
                    auto delim = key.find('|');
                    std::string funcName = key.substr(0, delim);
                    std::string detail = funcAnalysis[key];

                    std::cout << "   Calls    : " << funcName << "\n";
                    std::cout << "   Risk     : " << riskGroup << "\n";
                    std::cout << "   Analysis : " << detail << "\n";
                    std::cout << "   Addresses: ";
                    for (size_t i = 0; i < addrs.size(); ++i) {
                        std::cout << "0x" << addrs[i];
                        if (i + 1 != addrs.size()) std::cout << ", ";
                    }
                    std::cout << "\n\n";
                }

            }
        }
    }

    printSeparator(oss, "HEAP OVERFLOW ANALYSIS");
    HeapOverflowDetector heapDet;
    auto heapFindings = heapDet.detect(funcs);

    if (heapFindings.empty()) {
        oss << "✓ No heap overflow vulnerabilities detected.\n";
    } else {
        for (const auto& h : heapFindings) {
            if (!h.funcName.empty())
                oss << "   Potential heap overflow in '" << h.funcName << "':\n";
            oss << "   Address: 0x" << h.instrAddr << "\n";
            oss << "   Detail : " << h.detail << "\n\n";
        }
    }

    printSeparator(oss, "COMMAND INJECTION ANALYSIS");
    CommandInjectionDetector cmdDet;
    auto cmdFindings = cmdDet.detect(funcs);

    if (cmdFindings.empty()) {
        oss << "✓ No command injection vulnerabilities detected.\n";
    } else {
        for (const auto& c : cmdFindings) {
            if (!c.funcName.empty())
                oss << "   Potential command injection in '" << c.funcName << "':\n";
            oss << "   Address: 0x" << c.instrAddr << "\n";
            oss << "   Calls  : " << c.target << "\n";
            oss << "   Detail : " << c.detail << "\n\n";
        }
    }

    printSeparator(oss, "SUMMARY");
    int totalIssues = unsafeFindings.size() + heapFindings.size() + cmdFindings.size();

    oss << "Total issues found: " << totalIssues << "\n";
    oss << "├─ Unsafe function calls: " << unsafeFindings.size() << "\n";
    oss << "├─ Heap overflows       : " << heapFindings.size() << "\n";
    oss << "└─ Command injections   : " << cmdFindings.size() << "\n";

    if (totalIssues == 0) {
        oss << "\nBinary appears to be free of common vulnerability patterns.\n";
    } else {
        oss << "\nReview flagged issues carefully - some may be false positives.\n";
        oss << "   Focus on HIGH risk findings first.\n";
    }

    // Output full report to console
    std::cout << oss.str();

    // Ask for Gemini analysis
    std::cout << "\nWould you like to send the findings to Gemini for CTF-style exploit analysis? (y/n): ";
    std::string userInput;
    std::getline(std::cin, userInput);

    if (userInput == "y" || userInput == "Y") {
        std::ifstream promptFile("gemini_prompt.txt");
        std::stringstream promptStream;

        if (promptFile.is_open()) {
            promptStream << promptFile.rdbuf();
            promptFile.close();
        } else {
            std::cerr << "Could not read gemini_prompt.txt. Using fallback prompt.\n";
            promptStream << "CTF vulnerability findings:\n";
        }

        promptStream << "\n" << oss.str();
        std::string finalPrompt = promptStream.str();

        std::cout << "\nSending report to Gemini...\n";
        sendFindingsToGemini(finalPrompt);
    }

    return 0;
}
