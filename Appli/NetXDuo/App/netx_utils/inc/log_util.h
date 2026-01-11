/*
 * log_util.h
 *
 * Created on: Oct 24, 2025
 * Author: alpl_
 */

#ifndef INC_LOG_UTIL_H_
#define INC_LOG_UTIL_H_

// --- ANSI Color Definitions (VT100) ---
// \033 is the escape character. [34m sets foreground to Blue. [0m resets.
#define LOG_COLOR_BLUE  "\033[34m"
#define LOG_COLOR_RESET "\033[0m"


#ifdef __cplusplus
#include <iostream>

// Struct for C++ logging
struct LogLocation {
    const char* file;
    int line;
    const char* func;
};

// Stream insertion operator
inline std::ostream& operator<<(std::ostream& os, const LogLocation& loc) {
    // 1. Set Blue Color
    // 2. Print metadata
    // 3. Reset Color (so the actual log message after this is white/default)
    os << LOG_COLOR_BLUE
       << "[ $" << loc.file << "::" << loc.func << ": L# " << loc.line << "] "
       << LOG_COLOR_RESET;
    return os;
}

// Macro for use in C++ code
#define LOG_LOC LogLocation{__FILE__, __LINE__, __func__}

#else
#include <stdio.h>

// Macro for use in C code
// Uses compile-time string concatenation for the format string
#define LOG_LOC_C() \
    printf(LOG_COLOR_BLUE "[%s:%d - %s] " LOG_COLOR_RESET, __FILE__, __LINE__, __func__)

#endif

#endif /* INC_LOG_UTIL_H_ */
