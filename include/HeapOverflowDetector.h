// include/HeapOverflowDetector.h
#ifndef HEAP_OVERFLOW_DETECTOR_H
#define HEAP_OVERFLOW_DETECTOR_H

#include "Disassembler.h"
#include <vector>
#include <string>

class HeapOverflowDetector {
public:
    struct Finding {
        std::string funcName;
        std::string instrAddr;
        std::string detail;
    };
    std::vector<Finding> detect(const std::vector<Function>& funcs) const;
};

#endif // HEAP_OVERFLOW_DETECTOR_H