/***************************************************************************
 * cli.c -- CLI formatting and argument parsing helpers                    *
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

#include "cli.h"
#include <stdio.h>
#include <string.h>

#define OPT_STR_MAX 32

void
cli_print_help(const cli_app_t *app)
{
        size_t i;

        if (!app || !app->prog_name) {
                return;
        }

        fprintf(stderr, "Usage: %s %s\n", app->prog_name,
                app->usage_args ? app->usage_args : "");
        fprintf(stderr, "Options:\n");

        if (!app->options) {
                return;
        }

        for (i = 0; app->options[i].short_opt != '\0'; i++) {
                const cli_option_t *opt = &app->options[i];
                char opt_str[OPT_STR_MAX];
                const char *desc;

                if (opt->arg_name) {
                        snprintf(opt_str, sizeof(opt_str), "-%c <%s>",
                                 opt->short_opt, opt->arg_name);
                } else {
                        snprintf(opt_str, sizeof(opt_str), "-%c",
                                 opt->short_opt);
                }

                fprintf(stderr, "  %-14s  ", opt_str);

                desc = opt->description;
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
