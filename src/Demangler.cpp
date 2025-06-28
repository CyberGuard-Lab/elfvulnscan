// src/Demangler.cpp
#include "Demangler.h"
#include <array>
#include <memory>
#include <cstdio>

// Custom deleter for popen
struct FileCloser {
    void operator()(FILE* f) const noexcept { if (f) pclose(f); }
};

std::string Demangler::demangle(const std::string& name) const {
    std::string cmd = "c++filt " + name;
    std::array<char, 256> buf;
    std::string out;
    std::unique_ptr<FILE, FileCloser> pipe(popen(cmd.c_str(), "r"), FileCloser{});
    if (!pipe) return name;
    while (fgets(buf.data(), buf.size(), pipe.get())) out += buf.data();
    if (!out.empty() && out.back() == '\n') out.pop_back();
    return out.empty() ? name : out;
}