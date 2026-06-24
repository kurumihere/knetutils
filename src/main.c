#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int arping_cli_main(int argc, char *argv[]);
int ping_cli_main(int argc, char *argv[]);
int tcping_cli_main(int argc, char *argv[]);
int traceroute_cli_main(int argc, char *argv[]);

static const char *
get_basename(const char *path)
{
        const char *base = strrchr(path, '/');
        return base ? base + 1 : path;
}

int
main(int argc, char *argv[])
{
        if (argc < 1)
                return EXIT_FAILURE;

        const char *prog_name = get_basename(argv[0]);

        if (strcmp(prog_name, "arping") == 0) {
                return arping_cli_main(argc, argv);
        } else if (strcmp(prog_name, "ping") == 0) {
                return ping_cli_main(argc, argv);
        } else if (strcmp(prog_name, "tcping") == 0) {
                return tcping_cli_main(argc, argv);
        } else if (strcmp(prog_name, "traceroute") == 0) {
                return traceroute_cli_main(argc, argv);
        }

        if (argc < 2) {
                fprintf(stderr, "Usage: knetutils <command> [args]\n");
                fprintf(stderr, "Commands:\n");
                fprintf(stderr, "  arping\n");
                fprintf(stderr, "  ping\n");
                fprintf(stderr, "  tcping\n");
                fprintf(stderr, "  traceroute\n");
                return EXIT_FAILURE;
        }

        const char *cmd = argv[1];
        if (strcmp(cmd, "arping") == 0) {
                return arping_cli_main(argc - 1, argv + 1);
        } else if (strcmp(cmd, "ping") == 0) {
                return ping_cli_main(argc - 1, argv + 1);
        } else if (strcmp(cmd, "tcping") == 0) {
                return tcping_cli_main(argc - 1, argv + 1);
        } else if (strcmp(cmd, "traceroute") == 0) {
                return traceroute_cli_main(argc - 1, argv + 1);
        }

        fprintf(stderr, "knetutils: Unknown command '%s'\n", cmd);
        return EXIT_FAILURE;
}
