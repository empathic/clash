#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <spawn.h>

// Set to 1 to enable debug output
#define DEBUG_REDIRECT 1

#if DEBUG_REDIRECT
#define DEBUG_LOG(...) fprintf(stderr, "[shell_redirect] " __VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

static const char *target_binary = NULL;

__attribute__((constructor))
static void init(void) {
    DEBUG_LOG("Library loaded, pid=%d, target=%s\n", getpid(), getenv("SHELL_REDIRECT_TARGET") ?: "(not set)");
}

static const char *shells_to_redirect[] = {
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/zsh",
    NULL
};

static int should_redirect(const char *path) {
    if (!path) return 0;
    for (int i = 0; shells_to_redirect[i]; i++) {
        if (strcmp(path, shells_to_redirect[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static const char *get_target(void) {
    if (!target_binary) {
        target_binary = getenv("SHELL_REDIRECT_TARGET");
    }
    return target_binary;
}

static const char *redirect_path(const char *path) {
    const char *target = get_target();
    if (target && should_redirect(path)) {
        return target;
    }
    return path;
}

#ifdef __APPLE__
// macOS: Use DYLD_INTERPOSE mechanism

#define DYLD_INTERPOSE(_replacement,_original) \
    __attribute__((used)) static struct{ const void* replacement; const void* original; } _interpose_##_original \
    __attribute__((section("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_original }

// execv
int my_execv(const char *pathname, char *const argv[]) {
    const char *redirected = redirect_path(pathname);
    DEBUG_LOG("execv: %s -> %s\n", pathname, redirected);
    return execv(redirected, argv);
}
DYLD_INTERPOSE(my_execv, execv);

// execve
int my_execve(const char *pathname, char *const argv[], char *const envp[]) {
    const char *redirected = redirect_path(pathname);
    DEBUG_LOG("execve: %s -> %s\n", pathname, redirected);
    return execve(redirected, argv, envp);
}
DYLD_INTERPOSE(my_execve, execve);

// execvp
int my_execvp(const char *file, char *const argv[]) {
    return execvp(redirect_path(file), argv);
}
DYLD_INTERPOSE(my_execvp, execvp);

// stat
int my_stat(const char *pathname, struct stat *statbuf) {
    return stat(redirect_path(pathname), statbuf);
}
DYLD_INTERPOSE(my_stat, stat);

// lstat
int my_lstat(const char *pathname, struct stat *statbuf) {
    return lstat(redirect_path(pathname), statbuf);
}
DYLD_INTERPOSE(my_lstat, lstat);

// access
int my_access(const char *pathname, int mode) {
    return access(redirect_path(pathname), mode);
}
DYLD_INTERPOSE(my_access, access);

// open - needs special handling for varargs
int my_open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
        return open(redirect_path(pathname), flags, mode);
    }
    return open(redirect_path(pathname), flags);
}
DYLD_INTERPOSE(my_open, open);

// readlink
ssize_t my_readlink(const char *pathname, char *buf, size_t bufsiz) {
    return readlink(redirect_path(pathname), buf, bufsiz);
}
DYLD_INTERPOSE(my_readlink, readlink);

// realpath
char *my_realpath(const char *path, char *resolved_path) {
    return realpath(redirect_path(path), resolved_path);
}
DYLD_INTERPOSE(my_realpath, realpath);

// faccessat
int my_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    return faccessat(dirfd, redirect_path(pathname), mode, flags);
}
DYLD_INTERPOSE(my_faccessat, faccessat);

// fstatat
int my_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    return fstatat(dirfd, redirect_path(pathname), statbuf, flags);
}
DYLD_INTERPOSE(my_fstatat, fstatat);

// openat
int my_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
        return openat(dirfd, redirect_path(pathname), flags, mode);
    }
    return openat(dirfd, redirect_path(pathname), flags);
}
DYLD_INTERPOSE(my_openat, openat);

// posix_spawn - commonly used by node.js for child processes
int my_posix_spawn(pid_t *pid, const char *path,
                   const posix_spawn_file_actions_t *file_actions,
                   const posix_spawnattr_t *attrp,
                   char *const argv[], char *const envp[]) {
    const char *redirected = redirect_path(path);
    DEBUG_LOG("posix_spawn: %s -> %s\n", path, redirected);
    return posix_spawn(pid, redirected, file_actions, attrp, argv, envp);
}
DYLD_INTERPOSE(my_posix_spawn, posix_spawn);

// posix_spawnp - PATH-based variant
int my_posix_spawnp(pid_t *pid, const char *file,
                    const posix_spawn_file_actions_t *file_actions,
                    const posix_spawnattr_t *attrp,
                    char *const argv[], char *const envp[]) {
    const char *redirected = redirect_path(file);
    DEBUG_LOG("posix_spawnp: %s -> %s\n", file, redirected);
    return posix_spawnp(pid, redirected, file_actions, attrp, argv, envp);
}
DYLD_INTERPOSE(my_posix_spawnp, posix_spawnp);

#else
// Linux: Use dlsym(RTLD_NEXT, ...) mechanism

typedef int (*execve_fn)(const char *, char *const[], char *const[]);
int execve(const char *pathname, char *const argv[], char *const envp[]) {
    static execve_fn real_execve = NULL;
    if (!real_execve) real_execve = (execve_fn)dlsym(RTLD_NEXT, "execve");
    return real_execve(redirect_path(pathname), argv, envp);
}

typedef int (*execv_fn)(const char *, char *const[]);
int execv(const char *pathname, char *const argv[]) {
    static execv_fn real_execv = NULL;
    if (!real_execv) real_execv = (execv_fn)dlsym(RTLD_NEXT, "execv");
    return real_execv(redirect_path(pathname), argv);
}

typedef int (*execvp_fn)(const char *, char *const[]);
int execvp(const char *file, char *const argv[]) {
    static execvp_fn real_execvp = NULL;
    if (!real_execvp) real_execvp = (execvp_fn)dlsym(RTLD_NEXT, "execvp");
    return real_execvp(redirect_path(file), argv);
}

typedef int (*execvpe_fn)(const char *, char *const[], char *const[]);
int execvpe(const char *file, char *const argv[], char *const envp[]) {
    static execvpe_fn real_execvpe = NULL;
    if (!real_execvpe) real_execvpe = (execvpe_fn)dlsym(RTLD_NEXT, "execvpe");
    return real_execvpe(redirect_path(file), argv, envp);
}

typedef int (*stat_fn)(const char *, struct stat *);
int stat(const char *pathname, struct stat *statbuf) {
    static stat_fn real_stat = NULL;
    if (!real_stat) real_stat = (stat_fn)dlsym(RTLD_NEXT, "stat");
    return real_stat(redirect_path(pathname), statbuf);
}

typedef int (*lstat_fn)(const char *, struct stat *);
int lstat(const char *pathname, struct stat *statbuf) {
    static lstat_fn real_lstat = NULL;
    if (!real_lstat) real_lstat = (lstat_fn)dlsym(RTLD_NEXT, "lstat");
    return real_lstat(redirect_path(pathname), statbuf);
}

typedef int (*open_fn)(const char *, int, ...);
int open(const char *pathname, int flags, ...) {
    static open_fn real_open = NULL;
    if (!real_open) real_open = (open_fn)dlsym(RTLD_NEXT, "open");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
        return real_open(redirect_path(pathname), flags, mode);
    }
    return real_open(redirect_path(pathname), flags);
}

typedef int (*access_fn)(const char *, int);
int access(const char *pathname, int mode) {
    static access_fn real_access = NULL;
    if (!real_access) real_access = (access_fn)dlsym(RTLD_NEXT, "access");
    return real_access(redirect_path(pathname), mode);
}

typedef int (*faccessat_fn)(int, const char *, int, int);
int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    static faccessat_fn real_faccessat = NULL;
    if (!real_faccessat) real_faccessat = (faccessat_fn)dlsym(RTLD_NEXT, "faccessat");
    return real_faccessat(dirfd, redirect_path(pathname), mode, flags);
}

typedef ssize_t (*readlink_fn)(const char *, char *, size_t);
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    static readlink_fn real_readlink = NULL;
    if (!real_readlink) real_readlink = (readlink_fn)dlsym(RTLD_NEXT, "readlink");
    return real_readlink(redirect_path(pathname), buf, bufsiz);
}

typedef char *(*realpath_fn)(const char *, char *);
char *realpath(const char *path, char *resolved_path) {
    static realpath_fn real_realpath = NULL;
    if (!real_realpath) real_realpath = (realpath_fn)dlsym(RTLD_NEXT, "realpath");
    return real_realpath(redirect_path(path), resolved_path);
}

#endif
