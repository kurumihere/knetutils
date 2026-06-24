#include "arping.h"
#include "net.h"
#include "utils.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
print_usage(const char *prog_name)
{
        fprintf(stderr, "Usage: %s -I interface [options] <destination>\n",
                prog_name);
        fprintf(stderr, "Options:\n");
        fprintf(stderr,
                "  -I <interface>  specify network interface (e.g. eth0)\n");
        fprintf(stderr,
                "  -c <count>      stop after sending count ARP requests\n");
        fprintf(stderr, "  -w <timeout>    time to wait for reply in "
                        "milliseconds (default 1000)\n");
        fprintf(stderr, "  -i <interval>   time to wait between requests in "
                        "milliseconds (default 1000)\n");
        fprintf(stderr, "  -S <source_ip>  specify source IP address (default "
                        "is interface IP)\n");
        fprintf(stderr, "  -U              unsolicited ARP mode (updates "
                        "neighbors' ARP caches)\n");
        fprintf(stderr,
                "  -d              duplicate Address Detection (DAD) mode\n");
        fprintf(stderr, "  -G              use default gateway as target\n");
        fprintf(stderr, "  -C              cisco style output (! for reply, . "
                        "for timeout)\n");
        fprintf(stderr, "  -f              quit on first reply\n");
        fprintf(stderr,
                "  -A              send ARP Reply instead of Request\n");
        fprintf(stderr, "  -b              keep broadcasting (do not switch to "
                        "unicast after first reply)\n");
        fprintf(stderr, "  -u <unit>       time unit for output (ns, μs, ms). "
                        "default: auto-scaling\n");
        fprintf(stderr, "  -q              quiet output\n");
        fprintf(stderr, "  -h              print help and exit\n");
}

int
arping_cli_main(int argc, char *argv[])
{
        arping_config_t config;
        memset(&config, 0, sizeof(config));

        config.count = 0;
        config.timeout_ns = 1000000000ULL;
        config.interval_ns = 1000000000ULL;

        const char *source_ip_str = NULL;
        int opt;
        while ((opt = getopt(argc, argv, "I:c:w:i:S:qUdGCfAbu:h")) != -1) {
                switch (opt) {
                case 'I':
                        config.iface = optarg;
                        break;
                case 'c':
                        config.count = (uint32_t)atoi(optarg);
                        break;
                case 'w':
                        config.timeout_ns = (uint64_t)atoi(optarg) * 1000000ULL;
                        break;
                case 'i':
                        config.interval_ns =
                            (uint64_t)atoi(optarg) * 1000000ULL;
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
                        print_usage(argv[0]);
                        return EXIT_SUCCESS;
                default:
                        print_usage(argv[0]);
                        return EXIT_FAILURE;
                }
        }

        if (!config.iface) {
                log_err("Network interface is required (-I option)");
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }

        if (!net_get_iface_mac(config.iface, config.source_mac)) {
                die("Failed to get MAC address for interface %s", config.iface);
        }

        if (config.dad) {
                config.source_ip = 0;
        } else if (source_ip_str) {
                if (!net_resolve_ipv4(source_ip_str, &config.source_ip)) {
                        die("Invalid source IP address or hostname: %s",
                            source_ip_str);
                }
        } else {
                if (!net_get_iface_ip(config.iface, &config.source_ip)) {
                        log_warn("Failed to get IP address for interface %s, "
                                 "using 0.0.0.0",
                                 config.iface);
                        config.source_ip = 0;
                }
        }

        if (config.gateway) {
                if (!net_get_default_gateway(config.iface, &config.target_ip)) {
                        die("Failed to automatically determine the default "
                            "gateway");
                }
        } else if (config.unsolicited) {
                config.target_ip = config.source_ip;
        } else {
                if (optind >= argc) {
                        log_err("Missing destination IP address");
                        print_usage(argv[0]);
                        return EXIT_FAILURE;
                }
                const char *target_ip_str = argv[optind];
                if (!net_resolve_ipv4(target_ip_str, &config.target_ip)) {
                        die("Invalid target IP address or hostname: %s",
                            target_ip_str);
                }
        }

        if (config.cisco_style && config.count == 0) {
                config.count = 5;
        }

        if (getuid() != 0) {
                log_warn(
                    "arping may require root privileges to open raw sockets.");
        }

        return arping_run(&config);
}
