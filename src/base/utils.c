/***************************************************************************
 * utils.c -- Shared utility functions (time, logging, formatting)         *
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

#include "utils.h"
#include "cli.h"
#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void
log_err(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    fprintf(stderr, COLOR_BOLD COLOR_RED "[ERROR] " COLOR_RESET);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void
log_warn(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    fprintf(stderr, COLOR_BOLD COLOR_YELLOW "[WARN] " COLOR_RESET);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void
log_info(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    fprintf(stdout, COLOR_BOLD COLOR_CYAN "[INFO] " COLOR_RESET);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    va_end(args);
}

void
die(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    fprintf(stderr, COLOR_BOLD COLOR_RED "[FATAL] " COLOR_RESET);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);

    exit(EXIT_FAILURE);
}

u_int64_t
get_time_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        die("clock_gettime failed");
    }

    return (u_int64_t)ts.tv_sec * NS_PER_S + (u_int64_t)ts.tv_nsec;
}

u_int64_t
time_diff_ns(u_int64_t start, u_int64_t end)
{

    if (end < start) {
        return 0;
    }
    return end - start;
}

const char *
format_time(u_int64_t time_ns, const char *unit_choice, char *buf,
            size_t buf_size)
{
    if (unit_choice) {
        if (strcmp(unit_choice, "ns") == 0) {

            snprintf(buf, buf_size, "%llu ns", (unsigned long long)time_ns);
            return buf;
        } else if (strcmp(unit_choice, "us") == 0 ||
                   strcmp(unit_choice, "μs") == 0) {
            snprintf(buf, buf_size, "%.3f μs",
                     (double)time_ns / (double)NS_PER_US);
            return buf;
        } else if (strcmp(unit_choice, "ms") == 0) {
            snprintf(buf, buf_size, "%.3f ms",
                     (double)time_ns / (double)NS_PER_MS);
            return buf;
        }
    }

    if (time_ns < NS_PER_US) {
        snprintf(buf, buf_size, "%llu ns", (unsigned long long)time_ns);
    } else if (time_ns < NS_PER_MS) {
        snprintf(buf, buf_size, "%.3f μs", (double)time_ns / (double)NS_PER_US);
    } else {
        snprintf(buf, buf_size, "%.3f ms", (double)time_ns / (double)NS_PER_MS);
    }

    return buf;
}
