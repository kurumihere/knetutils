/***************************************************************************
 * pscan_cli.c -- CLI wrapper for the pscan utility                        *
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

#include "cli.h"
#include "net.h"
#include "pscan.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const cli_option_t pscan_options[] = {
    {'4', NULL, "use IPv4"},
    {'6', NULL, "use IPv6"},
    {'j', NULL, "output in JSON format"},
    {'O', NULL, "enable OS fingerprinting"},
    {'p', "ports", "port range to scan (e.g. 1-1024 or 80)"},
    {'R', NULL, "randomize port scanning order"},
    {'r', "rate", "max packets per second (rate limit)"},
    {'s', NULL, "service banner grabbing"},
    {'u', NULL, "use UDP scan instead of TCP SYN"},
    {'W', "timeout", "time to wait for a response, in seconds"},
    {'I', "iface/ip", "bind to a specific interface or IP address"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};
/*
 *		P R I N T _ U S A G E
 *
 * Logic for print_usage.
 */

static void
print_usage(const char *prog_name)
{
        cli_app_t app = {.prog_name = prog_name,
                         .usage_args = "[options] <destination>",
                         .options = pscan_options};
        cli_print_help(&app);
}

/*
 *		P S C A N _ C L I _ M A I N
 *
 * Parse arguments and execute the pscan tool.
 */
int
pscan_cli_main(int c, char **av)
{
        pscan_config_t config;
        int ch;
        const char *target_ip_str;

        memset(&config, 0, sizeof(config));

        config.family = AF_UNSPEC;
        config.timeout_ns = 2 * NS_PER_S;
        config.start_port = 1;
        config.end_port = 1024;

        while ((ch = getopt(c, av, "46jOp:r:W:I:Rsuh")) != -1) {
                switch (ch) {
                case 'u':
                        /* Enable UDP port scanning instead of TCP SYN scanning.
                         */
                        config.udp = true;
                        break;
                case 's':
                        config.banner_grab = true;
                        break;
                case 'O':
                        /* Enable OS fingerprinting via TCP/IP header
                         * inspection.  */
                        config.os_fingerprint = true;
                        break;
                case 'j':
                        config.json_output = true;
                        break;
                case 'R':
                        config.randomize = true;
                        break;
                case '4':
                        config.family = AF_INET;
                        break;
                case '6':
                        config.family = AF_INET6;
                        break;
                case 'p': {
                        /* Extract start and end port numbers for the scan
                         * range.  */
                        char *dash = strchr(optarg, '-');
                        if (dash) {
                                *dash = '\0';
                                config.start_port = (u_short)atoi(optarg);
                                config.end_port = (u_short)atoi(dash + 1);
                        } else {
                                config.start_port = (u_short)atoi(optarg);
                                config.end_port = config.start_port;
                        }
                        if (config.start_port == 0 || config.end_port == 0 ||
                            config.start_port > config.end_port) {
                                die("Invalid port range");
                                /* NOT REACHED */
                        }
                        break;
                }
                case 'W':
                        config.timeout_ns = (u_int64_t)atoi(optarg) * NS_PER_S;
                        break;
                case 'r':
                        config.rate_limit = (u_int)atoi(optarg);
                        break;
                case 'I':
                        config.bind_iface = optarg;
                        break;
                case 'h':
                        print_usage(*av);
                        return EXIT_SUCCESS;
                default:
                        print_usage(*av);
                        return EXIT_FAILURE;
                }
        }

        c -= optind;
        av += optind;

        if (c < 1) {
                log_err("Target IP/hostname is required");
                return EXIT_FAILURE;
        }

        target_ip_str = *av;

        if (!net_resolve_host(target_ip_str, config.family, &config.target_addr,
                              &config.target_addr_len)) {
                die("Invalid target IP address or hostname: %s", target_ip_str);
                /* NOT REACHED */
        }

        return pscan_run(&config);
}
