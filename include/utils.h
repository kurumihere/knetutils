/***************************************************************************
 * utils.h -- Header definitions for utility functions                     *
 *                                                                         *
 ***********************IMPORTANT KNETUTILS LICENSE TERMS******************* *
 *                                                                         *
 * knetutils is (C) 2026 kurumihere                                        *
 *                                                                         *
 * Redistribution and use in source and binary forms, with or without      *
 * modification, are permitted provided that the following conditions are  *
 * met:                                                                    *
 *                                                                         *
 * 1. Redistributions of source code must retain the above copyright       *
 *    notice, this list of conditions and the following disclaimer.        *
 *                                                                         *
 * 2. Redistributions in binary form must reproduce the above copyright    *
 *    notice, this list of conditions and the following disclaimer in the  *
 *    documentation and/or other materials provided with the distribution. *
 *                                                                         *
 * 3. Neither the name of the copyright holder nor the names of its        *
 *    contributors may be used to endorse or promote products derived from *
 *    this software without specific prior written permission.             *
 *                                                                         *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS     *
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT       *
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A *
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      *
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,  *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT        *
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   *
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY   *
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT     *
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE   *
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.    *
 *                                                                         *
 ***************************************************************************/

#ifndef KNETUTILS_UTILS_H
#define KNETUTILS_UTILS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define COLOR_RESET "\x1b[0m"
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_BOLD "\x1b[1m"

#define NS_PER_S 1000000000ULL
#define NS_PER_MS 1000000ULL
#define NS_PER_US 1000ULL

void log_err(const char *fmt, ...);

void log_warn(const char *fmt, ...);

void log_info(const char *fmt, ...);

void die(const char *fmt, ...) __attribute__((noreturn));

u_int64_t get_time_ns(void);

u_int64_t time_diff_ns(u_int64_t start, u_int64_t end);

const char *format_time(u_int64_t time_ns, const char *unit_choice, char *buf,
                        size_t buf_size);

#endif
