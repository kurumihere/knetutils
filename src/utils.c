#include "utils.h"
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
        fprintf(stderr, COLOR_BOLD COLOR_YELLOW "[WARN]  " COLOR_RESET);
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        va_end(args);
}

void
log_info(const char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        fprintf(stdout, COLOR_BOLD COLOR_CYAN "[INFO]  " COLOR_RESET);
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

uint64_t
get_time_ns(void)
{
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
                die("clock_gettime failed");
        }
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

uint64_t
time_diff_ns(uint64_t start, uint64_t end)
{
        if (end < start)
                return 0;
        return end - start;
}

const char *
format_time(uint64_t time_ns, const char *unit_choice, char *buf,
            size_t buf_size)
{
        if (unit_choice) {
                if (strcmp(unit_choice, "ns") == 0) {
                        snprintf(buf, buf_size, "%llu ns",
                                 (unsigned long long)time_ns);
                        return buf;
                } else if (strcmp(unit_choice, "us") == 0 ||
                           strcmp(unit_choice, "μs") == 0) {
                        snprintf(buf, buf_size, "%.3f μs",
                                 (double)time_ns / 1000.0);
                        return buf;
                } else if (strcmp(unit_choice, "ms") == 0) {
                        snprintf(buf, buf_size, "%.3f ms",
                                 (double)time_ns / 1000000.0);
                        return buf;
                }
        }

        if (time_ns < 1000) {
                snprintf(buf, buf_size, "%llu ns", (unsigned long long)time_ns);
        } else if (time_ns < 1000000) {
                snprintf(buf, buf_size, "%.3f μs", (double)time_ns / 1000.0);
        } else {
                snprintf(buf, buf_size, "%.3f ms", (double)time_ns / 1000000.0);
        }
        return buf;
}
