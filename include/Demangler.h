// include/Demangler.h
#ifndef DEMANGLER_H
#define DEMANGLER_H

#include <string>

class Demangler {
public:
    // Demangle C++ mangled symbol; returns cleaned name or original
    std::string demangle(const std::string& name) const;
};

#endif // DEMANGLER_H