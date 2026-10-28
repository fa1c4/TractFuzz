#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *message) {
    perror(message);
    exit(1);
}

static void allow(int ruleset, const char *path, __u64 access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) fail(path);
    struct landlock_path_beneath_attr rule = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH,
                &rule, 0) < 0) fail("landlock_add_rule");
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 4 || strcmp(argv[2], "--") != 0) {
        fprintf(stderr, "usage: eval-workspace-landlock WORKSPACE -- COMMAND [ARGS...]\n");
        return 2;
    }
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 3) {
        fprintf(stderr, "Landlock ABI 3 or newer is required for write confinement\n");
        return 1;
    }
    __u64 writes = LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
        LANDLOCK_ACCESS_FS_TRUNCATE;
    struct landlock_ruleset_attr ruleset = {.handled_access_fs = writes};
    int fd = syscall(SYS_landlock_create_ruleset, &ruleset, sizeof(ruleset), 0);
    if (fd < 0) fail("landlock_create_ruleset");
    allow(fd, argv[1], writes);
    allow(fd, "/dev/null", LANDLOCK_ACCESS_FS_WRITE_FILE |
          LANDLOCK_ACCESS_FS_TRUNCATE);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) fail("prctl");
    if (syscall(SYS_landlock_restrict_self, fd, 0) < 0) fail("landlock_restrict_self");
    close(fd);
    execvp(argv[3], &argv[3]);
    fail(argv[3]);
}
