#ifndef KNETUTILS_UTILS_H
#define KNETUTILS_UTILS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define COLOR_RESET "\x1b[0m"
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_BOLD "\x1b[1m"

void log_err(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_info(const char *fmt, ...);
void die(const char *fmt, ...) __attribute__((noreturn));

uint64_t get_time_ns(void);
uint64_t time_diff_ns(uint64_t start, uint64_t end);

const char *format_time(uint64_t time_ns, const char *unit_choice, char *buf,
                        size_t buf_size);

#endif
