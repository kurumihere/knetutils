#include "cli.h"
#include <stdio.h>
#include <string.h>

void
cli_print_help(const cli_app_t *app)
{
        if (!app || !app->prog_name) {
                return;
        }

        fprintf(stderr, "Usage: %s %s\n", app->prog_name,
                app->usage_args ? app->usage_args : "");
        fprintf(stderr, "Options:\n");

        if (!app->options) {
                return;
        }

        for (size_t i = 0; app->options[i].short_opt != '\0'; i++) {
                const cli_option_t *opt = &app->options[i];

                char opt_str[32];
                if (opt->arg_name) {
                        snprintf(opt_str, sizeof(opt_str), "-%c <%s>",
                                 opt->short_opt, opt->arg_name);
                } else {
                        snprintf(opt_str, sizeof(opt_str), "-%c",
                                 opt->short_opt);
                }

                fprintf(stderr, "  %-14s  ", opt_str);

                const char *desc = opt->description;
                while (*desc) {
                        if (*desc == '\n') {
                                fprintf(stderr, "\n                  ");
                        } else {
                                fputc(*desc, stderr);
                        }
                        desc++;
                }
                fprintf(stderr, "\n");
        }
}
