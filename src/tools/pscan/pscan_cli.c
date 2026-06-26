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
    {'p', "ports", "port range to scan (e.g. 1-1024 or 80)"},
    {'R', NULL, "randomize port scanning order"},
    {'r', "rate", "max packets per second (rate limit)"},
    {'s', NULL, "service banner grabbing"},
    {'u', NULL, "use UDP scan instead of TCP SYN"},
    {'W', "timeout", "time to wait for a response, in seconds"},
    {'I', "iface/ip", "bind to a specific interface or IP address"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

static void
print_usage(const char *prog_name)
{
        cli_app_t app = {.prog_name = prog_name,
                         .usage_args = "[options] <destination>",
                         .options = pscan_options};
        cli_print_help(&app);
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
        const char *target_ip_str;

        while ((opt = getopt(argc, argv, "46jp:r:W:I:Rsuh")) != -1) {
                switch (opt) {
                case 'u':
                        config.udp = true;
                        break;
                case 's':
                        config.banner_grab = true;
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
                        config.timeout_ns = (uint64_t)atoi(optarg) * NS_PER_S;
                        break;
                case 'r':
                        config.rate_limit = (uint32_t)atoi(optarg);
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

        target_ip_str = argv[optind];

        if (!net_resolve_host(target_ip_str, config.family, &config.target_addr,
                              &config.target_addr_len)) {
                die("Invalid target IP address or hostname: %s", target_ip_str);
        }

        return pscan_run(&config);
}
