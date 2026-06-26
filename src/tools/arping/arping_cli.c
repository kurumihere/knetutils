/***************************************************************************
 * arping_cli.c -- CLI wrapper for the arping utility                      *
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

#include "arping.h"
#include "net.h"
#include "utils.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"

static const cli_option_t arping_options[] = {
    {'I', "interface", "specify network interface (e.g. eth0)"},
    {'c', "count", "stop after sending count ARP requests"},
    {'w', "timeout", "time to wait for reply in milliseconds (default 1000)"},
    {'i', "interval",
     "time to wait between requests in milliseconds (default 1000)"},
    {'S', "source_ip", "specify source IP address (default is interface IP)"},
    {'U', NULL, "unsolicited ARP mode (updates neighbors' ARP caches)"},
    {'d', NULL, "duplicate address detection (DAD) mode"},
    {'G', NULL, "use default gateway as target"},
    {'C', NULL, "cisco style output (! for reply, . for timeout)"},
    {'f', NULL, "quit on first reply"},
    {'A', NULL, "send ARP reply instead of request"},
    {'b', NULL,
     "keep broadcasting (do not switch to unicast after first reply)"},
    {'u', "unit", "time unit for output (ns, μs, ms). default: auto-scaling"},
    {'q', NULL, "quiet output"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

static void
print_usage(const char *prog_name)
{
    cli_app_t app = {.prog_name = prog_name,
                     .usage_args = "-I interface [options] <destination>",
                     .options = arping_options};
    cli_print_help(&app);
}

int
arping_cli_main(int c, char **av)
{
    arping_config_t config;
    const char *source_ip_str = NULL;
    int ch;
    const char *target_ip_str;

    memset(&config, 0, sizeof(config));

    config.count = 0;
    config.timeout_ns = NS_PER_S;
    config.interval_ns = NS_PER_S;

    while ((ch = getopt(c, av, "I:c:w:i:S:qUdGCfAbu:h")) != -1) {
        switch (ch) {
        case 'I':
            config.iface = optarg;
            break;
        case 'c':
            config.count = (u_int)atoi(optarg);
            break;
        case 'w':
            config.timeout_ns = (u_int64_t)atoi(optarg) * NS_PER_MS;
            break;
        case 'i':
            config.interval_ns = (u_int64_t)atoi(optarg) * NS_PER_MS;
            break;
        case 'S':
            source_ip_str = optarg;
            break;
        case 'q':
            config.quiet = true;
            break;
        case 'U':
            config.unsolicited = true;
            break;
        case 'd':
            config.dad = true;
            break;
        case 'G':
            config.gateway = true;
            break;
        case 'C':
            config.cisco_style = true;
            break;
        case 'f':
            config.quit_on_reply = true;
            break;
        case 'A':
            config.use_reply = true;
            break;
        case 'b':
            config.keep_broadcast = true;
            break;
        case 'u':
            config.time_unit = optarg;
            break;
        case 'h':
            print_usage(*av);
            return EXIT_SUCCESS;
        default:
            print_usage(*av);
            goto err;
        }
    }

    if (!config.iface) {
        log_err("Network interface is required (-I option)");
        print_usage(*av);
        goto err;
    }

    c -= optind;
    av += optind;

    if (c < 1 && !config.gateway && !config.unsolicited) {
        log_err("Target IP/hostname is required");
        goto err;
    }

    if (!get_iface_mac(config.iface, config.source_mac)) {
        die("Failed to get MAC address for interface %s", config.iface);
    }

    if (config.dad) {

        config.source_ip = 0;
    } else if (source_ip_str) {
        if (!resolve_ipv4(source_ip_str, &config.source_ip)) {
            die("Invalid source IP address or hostname: %s", source_ip_str);
        }
    } else {
        if (!get_iface_addr(config.iface, &config.source_ip)) {
            log_warn("Failed to get IP address for interface %s, "
                     "using 0.0.0.0",
                     config.iface);
            config.source_ip = 0;
        }
    }

    if (config.gateway) {

        if (!get_default_gateway(config.iface, &config.target_ip)) {
            die("Failed to automatically determine the default "
                "gateway");
        }
    } else if (config.unsolicited) {
        config.target_ip = config.source_ip;
    } else {
        if (c < 1) {
            log_err("Missing destination IP address");
            print_usage(*av);
            goto err;
        }
        target_ip_str = *av;
        if (!resolve_ipv4(target_ip_str, &config.target_ip)) {
            die("Invalid target IP address or hostname: %s", target_ip_str);
        }
    }

    if (config.cisco_style && config.count == 0) {
        config.count = 5;
    }

    if (getuid() != 0) {
        log_warn("arping may require root privileges to open raw sockets.");
    }

    return arping_run(&config);

err:
    return EXIT_FAILURE;
}
