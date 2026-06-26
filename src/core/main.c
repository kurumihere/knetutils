#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int arping_cli_main(int argc, char *argv[]);
int ping_cli_main(int argc, char *argv[]);
int sniff_cli_main(int argc, char *argv[]);
int tcping_cli_main(int argc, char *argv[]);
int traceroute_cli_main(int argc, char *argv[]);
int pscan_cli_main(int argc, char *argv[]);

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
        fprintf(stderr, "  arping      discover and probe hosts on a local "
                        "network using ARP\n");
        fprintf(
            stderr,
            "  ping        send ICMP ECHO_REQUEST packets to network hosts\n");
        fprintf(
            stderr,
            "  pscan       fast asynchronous TCP SYN and UDP port scanner\n");
        fprintf(stderr, "  sniff       capture and display packets on a "
                        "network interface\n");
        fprintf(
            stderr,
            "  tcping      measure latency to a host using TCP SYN packets\n");
        fprintf(
            stderr,
            "  traceroute  print the route packets trace to network host\n\n");
        fprintf(stderr, "Run 'knetutils <command> -h' for more information on "
                        "a command.\n");
}

int
main(int argc, char *argv[])
{
        const char *prog_name;
        const char *cmd;

        if (argc < 1)
                return EXIT_FAILURE;

        prog_name = get_basename(argv[0]);

        if (strcmp(prog_name, "arping") == 0) {
                return arping_cli_main(argc, argv);
        } else if (strcmp(prog_name, "ping") == 0) {
                return ping_cli_main(argc, argv);
        } else if (strcmp(prog_name, "sniff") == 0) {
                return sniff_cli_main(argc, argv);
        } else if (strcmp(prog_name, "tcping") == 0) {
                return tcping_cli_main(argc, argv);
        } else if (strcmp(prog_name, "traceroute") == 0) {
                return traceroute_cli_main(argc, argv);
        } else if (strcmp(prog_name, "pscan") == 0) {
                return pscan_cli_main(argc, argv);
        }

        if (argc < 2) {
                print_main_usage();
                return EXIT_FAILURE;
        }

        cmd = argv[1];
        if (strcmp(cmd, "arping") == 0) {
                return arping_cli_main(argc - 1, argv + 1);
        } else if (strcmp(cmd, "ping") == 0) {
                return ping_cli_main(argc - 1, argv + 1);
        } else if (strcmp(cmd, "sniff") == 0) {
                return sniff_cli_main(argc - 1, argv + 1);
        } else if (strcmp(cmd, "tcping") == 0) {
                return tcping_cli_main(argc - 1, argv + 1);
        } else if (strcmp(cmd, "traceroute") == 0) {
                return traceroute_cli_main(argc - 1, argv + 1);
        } else if (strcmp(cmd, "pscan") == 0) {
                return pscan_cli_main(argc - 1, argv + 1);
        } else if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
                print_main_usage();
                return EXIT_SUCCESS;
        }

        fprintf(stderr, "knetutils: Unknown command '%s'\n", cmd);
        return EXIT_FAILURE;
}
