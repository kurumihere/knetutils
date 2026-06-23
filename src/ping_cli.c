#include "net.h"
#include "ping.h"
#include "utils.h"
#include <arpa/inet.h>
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
        fprintf(stderr, "  -c <count>      Stop after sending count "
                        "ECHO_REQUEST packets\n");
        fprintf(
            stderr,
            "  -w <timeout>    Time to wait for a response, in milliseconds\n");
        fprintf(stderr, "  -i <interval>   Wait interval milliseconds between "
                        "sending each packet\n");
        fprintf(stderr, "  -u <unit>       Time unit for output (ns, us, ms). "
                        "Default: auto-scaling\n");
        fprintf(stderr, "  -q              Quiet output\n");
        fprintf(stderr, "  -h              Print this help\n");
}

int
ping_cli_main(int argc, char *argv[])
{
        ping_config_t config;
        memset(&config, 0, sizeof(config));

        config.count = 0;
        config.timeout_ns = 1000000000ULL;
        config.interval_ns = 1000000000ULL;

        int opt;
        while ((opt = getopt(argc, argv, "c:w:i:u:qh")) != -1) {
                switch (opt) {
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
                case 'u':
                        config.time_unit = optarg;
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

        const char *target_ip_str = argv[optind];
        if (!net_parse_ipv4(target_ip_str, &config.target_ip)) {
                die("Invalid target IP address: %s", target_ip_str);
        }

        if (getuid() != 0) {
                log_warn(
                    "ping may require root privileges to open raw sockets.");
        }

        return ping_run(&config);
}
