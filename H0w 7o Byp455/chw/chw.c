#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void) {
    puts("chw - housekeeping for the scan pipeline");
    puts("usage:");
    puts("  chw list");
    puts("  chw archive --file <path> --profile <name>");
    puts("");
    puts("archive profiles: gzip, bzip2, xz, zstd (or point at your own");
    puts("compressor binary with --profile /path/to/binary)");
}

static void do_list(void) {
    system("ls -la /var/log/chw 2>/dev/null || echo '(no logs yet)'");
}

static void do_archive(const char *file, const char *profile) {
    if (!file || !profile) {
        usage();
        exit(1);
    }

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "%s -c %s > %s.chwarchive 2>/dev/null", profile, file, file);
    system(cmd);
    printf("archived %s with profile '%s'\n", file, profile);
}

int main(int argc, char **argv) {
    setuid(0);
    setgid(0);

    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        do_list();
        return 0;
    }

    if (strcmp(argv[1], "archive") == 0) {
        const char *file = NULL;
        const char *profile = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
                file = argv[++i];
            } else if (strcmp(argv[i], "--profile") == 0 && i + 1 < argc) {
                profile = argv[++i];
            }
        }
        do_archive(file, profile);
        return 0;
    }

    usage();
    return 1;
}
