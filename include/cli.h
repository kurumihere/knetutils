#ifndef KNETUTILS_CLI_H
#define KNETUTILS_CLI_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
        char short_opt;
        const char *arg_name;
        const char *description;
} cli_option_t;

typedef struct {
        const char *prog_name;
        const char *usage_args;
        const cli_option_t *options;
} cli_app_t;

void cli_print_help(const cli_app_t *app);

#endif
