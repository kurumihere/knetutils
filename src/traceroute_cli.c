#include "net.h"
#include "traceroute.h"
#include "utils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
print_usage(const char *prog_name)
{
        fprintf(stderr, "Usage: %s [options] <destination>\n", prog_name);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -4              use IPv4\n");
        fprintf(stderr, "  -6              use IPv6\n");
        fprintf(stderr,
                "  -f <first_ttl>  start from the given first_ttl hop\n");
        fprintf(stderr,
                "  -m <max_ttl>    set the max number of hops (max TTL)\n");
        fprintf(stderr, "  -q <nqueries>   set the number of probes per hop\n");
        fprintf(stderr,
                "  -w <timeout>    wait time for a response, in seconds\n");
        fprintf(stderr, "  -I <iface/ip>   bind to a specific interface or IP "
                        "address\n");
        fprintf(stderr,
                "  -n              do not resolve IP addresses to their domain "
                "names\n");
        fprintf(stderr, "  -h              print help and exit\n");
}

int
traceroute_cli_main(int argc, char *argv[])
{
        traceroute_config_t config;
        memset(&config, 0, sizeof(config));

        config.first_ttl = 1;
        config.max_ttl = 30;
        config.queries = 3;
        config.timeout_ns = 3000000000ULL; /* 3 seconds */
        config.family = AF_UNSPEC;
        config.resolve_hostnames = true;

        int opt;
        while ((opt = getopt(argc, argv, "46f:m:q:w:I:nh")) != -1) {
                switch (opt) {
                case '4':
                        config.family = AF_INET;
                        break;
                case '6':
                        config.family = AF_INET6;
                        break;
                case 'f':
                        config.first_ttl = (uint8_t)atoi(optarg);
                        break;
                case 'm':
                        config.max_ttl = (uint8_t)atoi(optarg);
                        break;
                case 'q':
                        config.queries = (uint8_t)atoi(optarg);
                        break;
                case 'w':
                        config.timeout_ns =
                            (uint64_t)atoi(optarg) * 1000000000ULL;
                        break;
                case 'I':
                        config.bind_iface = optarg;
                        break;
                case 'n':
                        config.resolve_hostnames = false;
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
        config.family = config.target_addr.ss_family;

        if (config.first_ttl == 0) {
                config.first_ttl = 1;
        }

        if (getuid() != 0) {
                log_warn("traceroute requires root privileges to open raw "
                         "sockets.");
        }

        return traceroute_run(&config);
}
