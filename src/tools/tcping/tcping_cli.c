#include "net.h"
#include "tcping.h"
#include "utils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
print_usage(const char *prog_name)
{
        fprintf(stderr, "Usage: %s [options] <destination> <port>\n",
                prog_name);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -4              use IPv4\n");
        fprintf(stderr, "  -6              use IPv6\n");
        fprintf(stderr, "  -c <count>      stop after sending count packets\n");
        fprintf(stderr,
                "  -W <timeout>    time to wait for a response, in seconds\n");
        fprintf(stderr, "  -i <interval>   wait interval milliseconds between "
                        "sending each packet\n");
        fprintf(stderr, "  -I <iface/ip>   bind to a specific interface or IP "
                        "address\n");
        fprintf(stderr, "  -q              quiet output\n");
        fprintf(stderr, "  -h              print help and exit\n");
}

int
tcping_cli_main(int argc, char *argv[])
{
        tcping_config_t config;
        memset(&config, 0, sizeof(config));

        config.count = 0;
        config.timeout_ns = 1000000000ULL;
        config.interval_ns = 1000000000ULL;
        config.family = AF_UNSPEC;

        int opt;
        while ((opt = getopt(argc, argv, "46c:W:i:I:qh")) != -1) {
                switch (opt) {
                case '4':
                        config.family = AF_INET;
                        break;
                case '6':
                        config.family = AF_INET6;
                        break;
                case 'c':
                        config.count = (uint32_t)atoi(optarg);
                        break;
                case 'W':
                        config.timeout_ns =
                            (uint64_t)atoi(optarg) * 1000000000ULL;
                        break;
                case 'i':
                        config.interval_ns =
                            (uint64_t)atoi(optarg) * 1000000ULL;
                        break;
                case 'I':
                        config.bind_iface = optarg;
                        break;
                case 'q':
                        config.quiet = true;
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

        if (optind + 1 >= argc) {
                log_err("Missing destination port");
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }

        const char *target_ip_str = argv[optind];
        config.port = (uint16_t)atoi(argv[optind + 1]);

        if (config.port == 0) {
                die("Invalid port: %s", argv[optind + 1]);
        }

        if (!net_resolve_host(target_ip_str, config.family, &config.target_addr,
                              &config.target_addr_len)) {
                die("Invalid target IP address or hostname: %s", target_ip_str);
        }
        config.family = config.target_addr.ss_family;

        if (getuid() != 0) {
                log_warn(
                    "tcping requires root privileges to open raw sockets.");
        }

        return tcping_run(&config);
}
