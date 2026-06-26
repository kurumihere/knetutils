#include "net.h"
#include "ping.h"
#include "utils.h"
#include <arpa/inet.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"

static const cli_option_t ping_options[] = {
    {'c', "count", "stop after sending count echo request packets"},
    {'w', "deadline", "specify a timeout, in seconds, before ping exits"},
    {'W', "timeout", "time to wait for a response, in seconds"},
    {'i', "interval", "wait interval milliseconds between sending each packet"},
    {'u', "unit", "time unit for output (ns, μs, ms). default: auto-scaling"},
    {'s', "size", "payload size in bytes"},
    {'p', "pattern", "hex pattern to fill payload (up to 16 bytes)"},
    {'Q', "tos", "quality of service / type of service"},
    {'t', "ttl", "time to live (TTL)"},
    {'a', NULL, "audible ping (print \\a on reply)"},
    {'A', NULL, "adaptive ping (interval adapts to RTT)"},
    {'f', NULL, "flood ping (prints . for send, \\b for recv)"},
    {'I', "iface/ip", "bind to a specific interface or IP address"},
    {'C', NULL, "cisco-style output"},
    {'q', NULL, "quiet output"},
    {'h', NULL, "print help and exit"},
    {0, NULL, NULL}};

static void
print_usage(const char *prog_name)
{
        cli_app_t app = {.prog_name = prog_name,
                         .usage_args = "[options] <destination>",
                         .options = ping_options};
        cli_print_help(&app);
}

int
ping_cli_main(int argc, char *argv[])
{
        ping_config_t config;
        int opt;
        const char *target_ip_str;

        memset(&config, 0, sizeof(config));

        config.count = 0;
        config.timeout_ns = NS_PER_S;
        config.interval_ns = NS_PER_S;
        config.payload_size = 56;
        config.ttl = 0;

        config.family = AF_UNSPEC;

        while ((opt = getopt(argc, argv, "46c:w:W:i:u:s:p:Q:t:I:aAqChf")) !=
               -1) {
                switch (opt) {
                case '4':
                        config.family = AF_INET;
                        break;
                case '6':
                        config.family = AF_INET6;
                        break;
                case 'C':
                        config.cisco_style = true;
                        break;
                case 'a':
                        config.audible = true;
                        break;
                case 'A':
                        config.adaptive = true;
                        break;
                case 'f':
                        config.flood = true;
                        config.interval_ns = 10 * NS_PER_MS;
                        break;
                case 'I':
                        config.bind_iface = optarg;
                        break;
                case 'c':
                        config.count = (uint32_t)atoi(optarg);
                        break;
                case 'w':
                        config.deadline_ns = (uint64_t)atoi(optarg) * NS_PER_S;
                        break;
                case 'W':
                        config.timeout_ns = (uint64_t)atoi(optarg) * NS_PER_S;
                        break;
                case 'i':
                        config.interval_ns = (uint64_t)atoi(optarg) * NS_PER_MS;
                        break;
                case 'u':
                        config.time_unit = optarg;
                        break;
                case 's':
                        config.payload_size = (uint32_t)atoi(optarg);
                        break;
                case 'p': {
                        size_t len = strlen(optarg);
                        size_t i;
                        if (len > 32)
                                len = 32;
                        config.pattern_len = len / 2;
                        for (i = 0; i < config.pattern_len; i++) {
                                unsigned int byte;
                                sscanf(optarg + i * 2, "%2x", &byte);
                                config.pattern[i] = (uint8_t)byte;
                        }
                        break;
                }
                case 'Q':
                        config.tos = (int)strtol(optarg, NULL, 0);
                        config.has_tos = true;
                        break;
                case 't':
                        config.ttl = (uint8_t)atoi(optarg);
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

        target_ip_str = argv[optind];
        if (!net_resolve_host(target_ip_str, config.family, &config.target_addr,
                              &config.target_addr_len)) {
                die("Invalid target IP address or hostname: %s", target_ip_str);
        }
        config.family = config.target_addr.ss_family;

        if (config.cisco_style && config.count == 0) {
                config.count = 5;
        }

        if (getuid() != 0) {
                log_warn(
                    "ping may require root privileges to open raw sockets.");
        }

        return ping_run(&config);
}
