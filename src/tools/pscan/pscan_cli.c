#include "cli.h"
#include "net.h"
#include "pscan.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
print_usage(const char *progname)
{
        printf("Usage: %s [options] <destination>\n", progname);
        printf("Options:\n");
        printf("  -4              use IPv4\n");
        printf("  -6              use IPv6\n");
        printf("  -p <start-end>  port range to scan (e.g. 1-1024 or 80)\n");
        printf("  -W <timeout>    time to wait for a response, in seconds\n");
        printf(
            "  -I <iface/ip>   bind to a specific interface or IP address\n");
        printf("  -h              print help and exit\n");
}

int
pscan_cli_main(int argc, char **argv)
{
        pscan_config_t config;
        memset(&config, 0, sizeof(config));

        config.family = AF_UNSPEC;
        config.timeout_ns = 2000000000ULL;
        config.start_port = 1;
        config.end_port = 1024;

        int opt;
        while ((opt = getopt(argc, argv, "46p:W:I:h")) != -1) {
                switch (opt) {
                case '4':
                        config.family = AF_INET;
                        break;
                case '6':
                        config.family = AF_INET6;
                        break;
                case 'p': {
                        char *dash = strchr(optarg, '-');
                        if (dash) {
                                *dash = '\0';
                                config.start_port = (uint16_t)atoi(optarg);
                                config.end_port = (uint16_t)atoi(dash + 1);
                        } else {
                                config.start_port = (uint16_t)atoi(optarg);
                                config.end_port = config.start_port;
                        }
                        if (config.start_port == 0 || config.end_port == 0 ||
                            config.start_port > config.end_port) {
                                die("Invalid port range");
                        }
                        break;
                }
                case 'W':
                        config.timeout_ns =
                            (uint64_t)atoi(optarg) * 1000000000ULL;
                        break;
                case 'I':
                        config.bind_iface = optarg;
                        break;
                case 'h':
                        print_usage(argv[0]);
                        return EXIT_SUCCESS;
                default:
                        print_usage(argv[0]);
                        return EXIT_FAILURE;
                }
        }

        if (optind >= argc) {
                log_err("Missing destination IP address");
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }

        const char *target_ip_str = argv[optind];

        if (!net_resolve_host(target_ip_str, config.family, &config.target_addr,
                              &config.target_addr_len)) {
                die("Invalid target IP address or hostname: %s", target_ip_str);
        }

        return pscan_run(&config);
}
