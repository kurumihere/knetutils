/***************************************************************************
 * main.c -- Core knetutils CLI entry point                                *
 *                                                                         *
 *********************IMPORTANT KNETUTILS LICENSE TERMS*********************
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
#include "tools.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN_ARGS 1
#define MIN_SUBCMD_ARGS 2

static const char *
get_basename(const char *path)
{
    const char *base = strrchr(path, '/');

    return base ? base + 1 : path;
}

static void
print_main_usage(void)
{
    fprintf(stderr, "knetutils - a collection of network utilities\n\n");
    fprintf(stderr, "Usage: knetutils <command> [args]\n\n");

    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  arping      discover and probe hosts on a local network "
                    "using ARP\n");
    fprintf(stderr,
            "  ping        send ICMP ECHO_REQUEST packets to network hosts\n");
    fprintf(stderr,
            "  pscan       fast asynchronous TCP SYN and UDP port scanner\n");
    fprintf(
        stderr,
        "  sniff       capture and display packets on a network interface\n");
    fprintf(stderr,
            "  tcping      measure latency to a host using TCP SYN packets\n");
    fprintf(stderr,
            "  traceroute  print the route packets trace to network host\n\n");

    fprintf(
        stderr,
        "Run 'knetutils <command> -h' for more information on a command.\n");
}

int
main(int c, char **av)
{
    const char *prog_name;
    const char *cmd;

    if (c < MIN_ARGS) {
        return EXIT_FAILURE;
    }

    prog_name = get_basename(*av);

    if (strcmp(prog_name, "arping") == 0) {
        return arping_main(c, av);
    } else if (strcmp(prog_name, "ping") == 0) {
        return ping_main(c, av);
    } else if (strcmp(prog_name, "sniff") == 0) {
        return sniff_main(c, av);
    } else if (strcmp(prog_name, "tcping") == 0) {
        return tcping_main(c, av);
    } else if (strcmp(prog_name, "traceroute") == 0) {
        return traceroute_main(c, av);
    } else if (strcmp(prog_name, "pscan") == 0) {
        return pscan_main(c, av);
    }

    if (c < MIN_SUBCMD_ARGS) {
        print_main_usage();
        return EXIT_FAILURE;
    }

    cmd = *(av + 1);

    if (strcmp(cmd, "arping") == 0) {
        return arping_main(c - 1, av + 1);
    } else if (strcmp(cmd, "ping") == 0) {
        return ping_main(c - 1, av + 1);
    } else if (strcmp(cmd, "sniff") == 0) {
        return sniff_main(c - 1, av + 1);
    } else if (strcmp(cmd, "tcping") == 0) {
        return tcping_main(c - 1, av + 1);
    } else if (strcmp(cmd, "traceroute") == 0) {
        return traceroute_main(c - 1, av + 1);
    } else if (strcmp(cmd, "pscan") == 0) {
        return pscan_main(c - 1, av + 1);
    } else if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        print_main_usage();
        return EXIT_SUCCESS;
    }

    fprintf(stderr, "knetutils: Unknown command '%s'\n", cmd);
    return EXIT_FAILURE;
}
