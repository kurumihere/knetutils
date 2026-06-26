/***************************************************************************
 * traceroute_cli.c -- CLI wrapper for the traceroute utility              *
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

#include "net.h"
#include "traceroute.h"
#include "utils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"

static const cli_option_t traceroute_options[] = {
    {'4', NULL, "use IPv4"},
    {'6', NULL, "use IPv6"},
    {'f', "first_ttl", "start from the given first_ttl hop"},
    {'m', "max_ttl", "set the max number of hops (max TTL)"},
    {'q', "nqueries", "set the number of probes per hop"},
    {'U', NULL, "use UDP instead of ICMP ECHO"},
    {'w', "timeout", "wait time for a response, in seconds"},
    {'I', "iface/ip", "bind to a specific interface or IP address"},
    {'n', NULL, "do not resolve IP addresses to their domain names"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

static void
print_usage(const char *prog_name)
{
        cli_app_t app = {.prog_name = prog_name,
                         .usage_args = "[options] <destination>",
                         .options = traceroute_options};

        cli_print_help(&app);
}

int
traceroute_cli_main(int c, char **av)
{
        traceroute_config_t config;
        int ch;
        const char *target_ip_str;
        const char *prog_name;

        int ret = EXIT_FAILURE;

        prog_name = *av;

        memset(&config, 0, sizeof(config));

        config.first_ttl = 1;
        config.max_ttl = 30;
        config.queries = 3;
        config.timeout_ns = 3 * NS_PER_S;
        config.family = AF_UNSPEC;
        config.resolve_hostnames = true;

        while ((ch = getopt(c, av, "46f:m:q:w:I:nUh")) != -1) {
                switch (ch) {
                case '4':

                        config.family = AF_INET;
                        break;
                case '6':
                        config.family = AF_INET6;
                        break;
                case 'f':
                        config.first_ttl = (u_char)atoi(optarg);
                        break;
                case 'm':
                        config.max_ttl = (u_char)atoi(optarg);
                        break;
                case 'q':
                        config.queries = (u_char)atoi(optarg);
                        break;
                case 'w':
                        config.timeout_ns = (u_int64_t)atoi(optarg) * NS_PER_S;
                        break;
                case 'I':
                        config.bind_iface = optarg;
                        break;
                case 'n':
                        config.resolve_hostnames = false;
                        break;
                case 'U':
                        config.use_udp = true;
                        break;
                case 'h':
                        print_usage(prog_name);
                        ret = EXIT_SUCCESS;
                        goto out;
                default:
                        goto usage_err;
                }
        }

        c -= optind;
        av += optind;

        if (c < 1) {
                log_err("Target IP/hostname is required");
                goto usage_err;
        }

        target_ip_str = *av;

        if (!net_resolve_host(target_ip_str, config.family, &config.target_addr,
                              &config.target_addr_len)) {
                die("Invalid target IP address or hostname: %s", target_ip_str);
                /* NOT REACHED */
        }

        config.family = config.target_addr.ss_family;

        if (config.first_ttl == 0) {
                config.first_ttl = 1;
        }

        if (getuid() != 0) {

                log_warn("traceroute requires root privileges to open raw "
                         "sockets.");
        }

        ret = traceroute_run(&config);
        goto out;

usage_err:
        print_usage(prog_name);

out:
        return ret;
}
