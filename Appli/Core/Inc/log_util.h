/*
 * log_util.h
 *
 *  Created on: Oct 24, 2025
 *      Author: alpl_
 */

#ifndef INC_LOG_UTIL_H_
#define INC_LOG_UTIL_H_


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
    os << "[ $" << loc.file << "::F@ " << loc.func << ": L# " << loc.line << "] ";
    return os;
}

// Macro for use in C++ code
#define LOG_LOC LogLocation{__FILE__, __LINE__, __func__}

#else
#include <stdio.h>

// Macro for use in C code
#define LOG_LOC_C() \
    printf("[%s:%d - %s] ", __FILE__, __LINE__, __func__)

#endif





#endif /* INC_LOG_UTIL_H_ */
