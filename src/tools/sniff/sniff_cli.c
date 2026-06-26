/***************************************************************************
 * sniff_cli.c -- CLI wrapper for the sniff utility                        *
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

#include "sniff.h"
#include "utils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"

static const cli_option_t sniff_options[] = {
    {'I', "iface", "interface to sniff on (required)"},
    {'c', "count", "stop after receiving count packets"},
    {'w', "file", "write packets to a PCAP file"},
    {'v', NULL,
     "increase verbosity (max level: 3, e.g. -vvv)\n-v   : show L4 headers "
     "(TCP/UDP/ICMP)\n-vv  : show L4 headers + payload hex-dump\n-vvv : show "
     "L4 headers + full packet hex-dump"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

/*
 *		P R I N T _ U S A G E
 *
 * Print the usage instructions for the sniff CLI utility.
 */
static void
print_usage(const char *prog_name)
{
        cli_app_t app = {.prog_name = prog_name,
                         .usage_args = "[options]",
                         .options = sniff_options};

        cli_print_help(&app);
}

/*
 *		S N I F F _ C L I _ M A I N
 *
 * Parse arguments and execute the sniff tool.
 */
int
sniff_cli_main(int c, char **av)
{
        sniff_config_t config;
        int ch;
        const char *prog_name;

        prog_name = *av;

        memset(&config, 0, sizeof(config));

        while ((ch = getopt(c, av, "I:c:w:vh")) != -1) {
                switch (ch) {
                case 'I':
                        config.iface = optarg;
                        break;
                case 'c':
                        config.max_packets = atoi(optarg);
                        break;
                case 'w':
                        /* Save captured packets to PCAP format file.  */
                        config.pcap_file = optarg;
                        break;
                case 'v':
                        config.verbosity++;
                        break;
                case 'h':
                        print_usage(prog_name);
                        return EXIT_SUCCESS;
                default:
                        print_usage(prog_name);
                        return EXIT_FAILURE;
                }
        }

        c -= optind;
        av += optind;

        if (!config.iface) {
                log_err("Interface is required (-I)");
                print_usage(prog_name);
                return EXIT_FAILURE;
        }

        /* Raw sockets require root capabilities.  */
        if (getuid() != 0) {
                log_warn("sniff requires root privileges to open raw sockets.");
        }

        return sniff_run(&config);
}
