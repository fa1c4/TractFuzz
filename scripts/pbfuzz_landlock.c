#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int landlock_create(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
    return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static int landlock_add(int ruleset_fd, enum landlock_rule_type type,
                        const void *attr, __u32 flags) {
    return syscall(SYS_landlock_add_rule, ruleset_fd, type, attr, flags);
}

static int landlock_restrict(int ruleset_fd, __u32 flags) {
    return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

static void die(const char *what) {
    fprintf(stderr, "pbfuzz-landlock: %s: %s\n", what, strerror(errno));
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: pbfuzz-landlock --allow PATH [--allow PATH ...] -- COMMAND [ARGS...]\n");
        return 2;
    }
    int abi = landlock_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) die("Landlock ABI check");
    struct landlock_ruleset_attr ruleset = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
    };
    int ruleset_fd = landlock_create(&ruleset, sizeof(ruleset), 0);
    if (ruleset_fd < 0) die("create ruleset");
    int i = 1;
    int paths = 0;
    for (; i < argc && strcmp(argv[i], "--") != 0; i += 2) {
        if (i + 1 >= argc || strcmp(argv[i], "--allow") != 0) {
            fprintf(stderr, "pbfuzz-landlock: expected --allow PATH\n");
            return 2;
        }
        int path_fd = open(argv[i + 1], O_PATH | O_CLOEXEC);
        if (path_fd < 0) die(argv[i + 1]);
        struct stat path_stat;
        if (fstat(path_fd, &path_stat) < 0) die(argv[i + 1]);
        struct landlock_path_beneath_attr rule = {
            .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                              (S_ISDIR(path_stat.st_mode) ? LANDLOCK_ACCESS_FS_READ_DIR : 0),
            .parent_fd = path_fd,
        };
        if (landlock_add(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) < 0) {
            die(argv[i + 1]);
        }
        close(path_fd);
        paths++;
    }
    if (i >= argc - 1 || paths == 0) {
        fprintf(stderr, "pbfuzz-landlock: missing -- COMMAND or allowlist\n");
        return 2;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die("no_new_privs");
    if (landlock_restrict(ruleset_fd, 0) < 0) die("restrict self");
    close(ruleset_fd);
    execvp(argv[i + 1], &argv[i + 1]);
    die(argv[i + 1]);
}
