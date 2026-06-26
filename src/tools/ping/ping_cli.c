/***************************************************************************
 * ping_cli.c -- CLI wrapper for the ping utility                          *
 *                                                                         *
 ************************IMPORTANT KNETUTILS LICENSE TERMS********************
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

#include "net.h"
#include "ping.h"
#include "utils.h"
#include <arpa/inet.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"

static const cli_option_t ping_options[] = {
    {'c', "count", "stop after sending count echo request packets"},
    {'w', "deadline", "specify a timeout, in seconds, before ping exits"},
    {'W', "timeout", "time to wait for a response, in seconds"},
    {'i', "interval", "wait interval milliseconds between sending each packet"},
    {'u', "unit", "time unit for output (ns, μs, ms). default: auto-scaling"},
    {'s', "size", "payload size in bytes"},
    {'p', "pattern", "hex pattern to fill payload (up to 16 bytes)"},
    {'Q', "tos", "quality of service / type of service"},
    {'t', "ttl", "time to live (TTL)"},
    {'a', NULL, "audible ping (print \\a on reply)"},
    {'A', NULL, "adaptive ping (interval adapts to RTT)"},
    {'f', NULL, "flood ping (prints . for send, \\b for recv)"},
    {'I', "iface/ip", "bind to a specific interface or IP address"},
    {'C', NULL, "cisco-style output"},
    {'q', NULL, "quiet output"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

static void
print_usage(const char *prog_name)
{
        cli_app_t app = {.prog_name = prog_name,
                         .usage_args = "[options] <destination>",
                         .options = ping_options};
        cli_print_help(&app);
}

int
ping_cli_main(int c, char **av)
{
        ping_config_t config;
        int ch;
        const char *target_ip_str;

        memset(&config, 0, sizeof(config));

        config.count = 0;
        config.timeout_ns = NS_PER_S;
        config.interval_ns = NS_PER_S;
        config.payload_size = 56;
        config.ttl = 0;

        config.family = AF_UNSPEC;

        while ((ch = getopt(c, av, "46c:w:W:i:u:s:p:Q:t:I:aAqChf")) != -1) {
                switch (ch) {
                case '4':

                        config.family = AF_INET;
                        break;
                case '6':
                        config.family = AF_INET6;
                        break;
                case 'C':
                        config.cisco_style = true;
                        break;
                case 'a':
                        config.audible = true;
                        break;
                case 'A':
                        config.adaptive = true;
                        break;
                case 'f':
                        config.flood = true;
                        config.interval_ns = 10 * NS_PER_MS;
                        break;
                case 'I':
                        config.bind_iface = optarg;
                        break;
                case 'c':
                        config.count = (u_int)atoi(optarg);
                        break;
                case 'w':
                        config.deadline_ns = (u_int64_t)atoi(optarg) * NS_PER_S;
                        break;
                case 'W':
                        config.timeout_ns = (u_int64_t)atoi(optarg) * NS_PER_S;
                        break;
                case 'i':
                        config.interval_ns =
                            (u_int64_t)atoi(optarg) * NS_PER_MS;
                        break;
                case 'u':
                        config.time_unit = optarg;
                        break;
                case 's':
                        config.payload_size = (u_int)atoi(optarg);
                        break;
                case 'p': {

                        size_t len = strlen(optarg);
                        size_t i;
                        if (len > 32)
                                len = 32;
                        config.pattern_len = len / 2;
                        for (i = 0; i < config.pattern_len; i++) {
                                unsigned int byte;
                                sscanf(optarg + i * 2, "%2x", &byte);
                                config.pattern[i] = (u_char)byte;
                        }
                        break;
                }
                case 'Q':

                        config.tos = (int)strtol(optarg, NULL, 0);
                        config.has_tos = true;
                        break;
                case 't':
                        config.ttl = (u_char)atoi(optarg);
                        break;
                case 'q':
                        config.quiet = true;
                        break;
                case 'h':
                        print_usage(*av);
                        return EXIT_SUCCESS;
                default:
                        print_usage(*av);
                        goto err;
                }
        }

        c -= optind;
        av += optind;

        if (c < 1) {
                log_err("Target IP/hostname is required");
                goto err;
        }

        target_ip_str = *av;
        if (!net_resolve_host(target_ip_str, config.family, &config.target_addr,
                              &config.target_addr_len)) {
                die("Invalid target IP address or hostname: %s", target_ip_str);
        }
        config.family = config.target_addr.ss_family;

        if (config.cisco_style && config.count == 0) {
                config.count = 5;
        }

        if (getuid() != 0) {
                log_warn(
                    "ping may require root privileges to open raw sockets.");
        }

        return ping_run(&config);

err:
        return EXIT_FAILURE;
}
