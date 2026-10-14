/*
 * pear-exec: the only way to reach the Pear Passwords daemon.
 *
 * Installed root:pear-client 2755. The daemon socket is 0660 to group pear-client, which has
 * no members, so effective gid pear-client is the identity "this is the genuine app". This
 * program hands that identity only to four fixed, root-owned targets, with an environment
 * built from scratch:
 *
 *   ui        /usr/bin/quickshell -p $P/app                       (the window)
 *   clip      $P/venv/bin/python -I -m icp.client.clip            (clipboard writer)
 *   migrate   $P/venv/bin/python -I -m icp.client.migrate         (v1 importer)
 *   autofill  $P/venv/bin/python -I -m icp.client.autofill        (browser native host)
 *
 * Because it is a set-gid exec, the kernel makes the target non-dumpable and AT_SECURE: a
 * process running as you cannot ptrace it, read its memory, fds or environment, or preload
 * code into it, whatever ptrace_scope says. Everything below is about not handing that
 * protected process anything you control: no inherited environment, no extra arguments, no
 * fds, and no target a non-root user could have replaced.
 *
 * The compositor check only raises the bar: the compositor runs as you and Wayland has no way
 * to authenticate it, so a program running as you could still start its own. It does stop a
 * WAYLAND_DISPLAY that points anywhere but the session's own Hyprland.
 *
 * Every path and name here must equal system/paths.env; backend/tests/test_pear_exec_env.py
 * checks that, and builds this file in test mode to check the environment it produces.
 *
 * Test mode (compile with -DPEAR_EXEC_TEST_MODE, never done by the installer): paths are
 * looked up under $PEAR_EXEC_TEST_ROOT, "root-owned" means owned by the caller, and the
 * set-gid identity check is skipped. A normal build ignores every PEAR_EXEC_TEST_* variable.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

/* --- must equal system/paths.env ------------------------------------------------------ */
#define PEAR_PREFIX             "/usr/local/lib/pear-passwords"
#define PEAR_VENV               "/usr/local/lib/pear-passwords/venv"
#define PEAR_VENV_PYTHON        "/usr/local/lib/pear-passwords/venv/bin/python"
#define PEAR_APP_DIR            "/usr/local/lib/pear-passwords/app"
#define PEAR_FONTS_CONF         "/usr/local/lib/pear-passwords/etc/fonts.conf"
#define PEAR_EMPTY_DIR          "/usr/local/lib/pear-passwords/empty"
#define PEAR_CLIENT_GROUP       "pear-client"
#define PEAR_TARGET_UI          "/usr/bin/quickshell"
#define PEAR_TARGET_CLIP_MODULE     "icp.client.clip"
#define PEAR_TARGET_MIGRATE_MODULE  "icp.client.migrate"
#define PEAR_TARGET_AUTOFILL_MODULE "icp.client.autofill"

/* Wayland interfaces the window's Qt must never bind (QT_WAYLAND_DISABLED_INTERFACES). */
#define QT_DISABLED_IFACES \
    "zwp_primary_selection_device_manager_v1,gtk_primary_selection_device_manager," \
    "zwp_text_input_manager_v1,zwp_text_input_manager_v2,zwp_text_input_manager_v3," \
    "qt_text_input_method_manager_v1"

/* The window's session bus: an address nothing can listen on (the empty directory is root's).
 * Qt starts its AT-SPI bridge from the session bus, and any program of yours can switch
 * org.a11y.Status IsEnabled on there - after which every field and label of the window,
 * revealed passwords included, could be read and its buttons pressed over the accessibility
 * bus. Without a session bus the bridge never starts. The window uses no D-Bus service; the
 * clip and migrate roles it starts get the real bus back from their own pear-exec. */
#define PEAR_NO_SESSION_BUS     "unix:path=/usr/local/lib/pear-passwords/empty/no-session-bus"

#define COMPOSITOR_COMM         "Hyprland"

#define EX_USAGE_   64      /* not exactly one known role */
#define EX_REFUSED  77      /* identity, environment or target check failed */
#define EX_EXECFAIL 70      /* execve itself failed */

#define MAX_ENV     64
#define MAX_VALUE   256

static const char *test_root = "";     /* "" in a normal build: paths are what they say */
static uid_t owner_uid = 0;            /* who must own every target path: root */

static void die(int code, const char *fmt, ...)
{
    va_list ap;
    fputs("pear-exec: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(code);
}

/* --- environment under construction --------------------------------------------------- */

static char *envv[MAX_ENV + 1];
static int envc = 0;

static void env_put(const char *name, const char *value)
{
    char *kv;
    if (envc >= MAX_ENV)
        die(EX_REFUSED, "environment too large");
    if (asprintf(&kv, "%s=%s", name, value) < 0)
        die(EX_REFUSED, "out of memory");
    envv[envc++] = kv;
    envv[envc] = NULL;
}

/* The only characters a passed-through value may contain: no spaces, slashes, quotes,
 * escapes or anything a toolkit could read as a path or a list. */
static int safe_value(const char *v)
{
    size_t n = 0;
    if (v == NULL || *v == '\0')
        return 0;
    for (; *v; v++, n++) {
        unsigned char c = (unsigned char)*v;
        if (n >= MAX_VALUE)
            return 0;
        if (!(isalnum(c) || c == '_' || c == '.' || c == '@' || c == '-'))
            return 0;
    }
    return 1;
}

static void pass_if_safe(const char *name)
{
    const char *v = getenv(name);
    if (safe_value(v))
        env_put(name, v);
}

/* --- small helpers ---------------------------------------------------------------------- */

static char *under_root(const char *path)
{
    char *p;
    if (asprintf(&p, "%s%s", test_root, path) < 0)
        die(EX_REFUSED, "out of memory");
    return p;
}

/* Read a small /proc file into buf, without following a symlink at the last component. */
static int read_small(const char *path, char *buf, size_t size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    ssize_t n;
    if (fd < 0)
        return -1;
    n = read(fd, buf, size - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return (int)n;
}

static int proc_comm_is(pid_t pid, const char *want)
{
    char path[64], buf[64];
    snprintf(path, sizeof path, "/proc/%d/comm", (int)pid);
    if (read_small(path, buf, sizeof buf) < 0)
        return 0;
    buf[strcspn(buf, "\n")] = '\0';
    return strcmp(buf, want) == 0;
}

/* Field 22 (starttime) of /proc/<pid>/stat, counted after the last ')' so a comm with spaces
 * or parens cannot shift the fields. p starts on the space before field 3 (state); each hop
 * moves to the space before the next field, so 19 hops (field 3 -> 22) land on starttime.
 * One more hop would read field 23, the virtual size (round 2 audit, problem 1). */
static int proc_starttime(pid_t pid, unsigned long long *out)
{
    char path[64], buf[1024], *p;
    int field;
    snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
    if (read_small(path, buf, sizeof buf) < 0)
        return -1;
    p = strrchr(buf, ')');
    if (p == NULL)
        return -1;
    p++;
    for (field = 3; field < 22; field++) {
        p = strchr(p + 1, ' ');
        if (p == NULL)
            return -1;
    }
    *out = strtoull(p + 1, NULL, 10);
    return 0;
}

static const char *compositor_comm(void)
{
#ifdef PEAR_EXEC_TEST_MODE
    const char *c = getenv("PEAR_EXEC_TEST_COMM");
    if (c && *c)
        return c;
#endif
    return COMPOSITOR_COMM;
}

/* --- checks ------------------------------------------------------------------------------ */

static void check_identity(uid_t ruid, gid_t *client_gid_out)
{
    const char *group = PEAR_CLIENT_GROUP;
    struct group *gr;
    gid_t groups[NGROUPS_MAX];
    int n, i;

    if (ruid == 0 || geteuid() == 0)
        die(EX_REFUSED, "refusing to run as root");

#ifdef PEAR_EXEC_TEST_MODE
    if (getenv("PEAR_EXEC_TEST_GROUP"))
        group = getenv("PEAR_EXEC_TEST_GROUP");
#endif
    gr = getgrnam(group);
#ifdef PEAR_EXEC_TEST_MODE
    if (gr == NULL) {
        *client_gid_out = (gid_t)-1;
        return;
    }
#else
    if (gr == NULL)
        die(EX_REFUSED, "group %s does not exist; run the system install step", group);
    /* Installed set-gid: the effective gid is the client group and the real one is not. */
    if (getegid() != gr->gr_gid || getgid() == gr->gr_gid)
        die(EX_REFUSED, "not installed set-gid %s; run the system install step", group);
#endif
    /* A member of the group would not need this program; the daemon refuses to start then,
     * and so does this. */
    n = getgroups(NGROUPS_MAX, groups);
    if (n < 0)
        die(EX_REFUSED, "getgroups failed");
    for (i = 0; i < n; i++)
        if (groups[i] == gr->gr_gid)
            die(EX_REFUSED, "%s must have no members, and you are one", group);
    *client_gid_out = gr->gr_gid;
}

static char *check_runtime_dir(uid_t ruid)
{
    char want[64], *rt;
    const char *have = getenv("XDG_RUNTIME_DIR");
    struct stat st;

    snprintf(want, sizeof want, "/run/user/%u", (unsigned)ruid);
    rt = under_root(want);
    if (have == NULL || strcmp(have, rt) != 0)
        die(EX_REFUSED, "XDG_RUNTIME_DIR must be %s", rt);
    if (lstat(rt, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ruid
        || (st.st_mode & 07777) != 0700)
        die(EX_REFUSED, "%s is not your private 0700 runtime directory", rt);
    return rt;
}

/* ^wayland-[0-9]+$ : a bare socket name in the runtime directory, never a path. */
static int wayland_name_ok(const char *name)
{
    const char *p;
    if (name == NULL || strncmp(name, "wayland-", 8) != 0 || name[8] == '\0')
        return 0;
    if (strlen(name) > 24)
        return 0;
    for (p = name + 8; *p; p++)
        if (!isdigit((unsigned char)*p))
            return 0;
    return 1;
}

static int sig_ok(const char *sig)
{
    const char *p;
    if (!safe_value(sig))
        return 0;
    /* safe_value allows '.', and "." or ".." would walk out of hypr/ */
    for (p = sig; *p == '.'; p++)
        ;
    return *p != '\0';
}

/* The compositor behind WAYLAND_DISPLAY must be this session's Hyprland: owned by you, comm
 * "Hyprland", named in its instance lock file, and the oldest Hyprland you own (the real
 * session starts first; a nested test instance is younger and still works for itself). */
static char *check_wayland(const char *rt, uid_t ruid)
{
    const char *name = getenv("WAYLAND_DISPLAY");
    size_t rt_len = strlen(rt);
    const char *sig = getenv("HYPRLAND_INSTANCE_SIGNATURE");
    const char *comm = compositor_comm();
    char *sock_path, *lock_path, buf[256], *line2;
    struct stat st;
    struct sockaddr_un addr;
    struct ucred cred;
    socklen_t len = sizeof cred;
    unsigned long long mine, other;
    long lock_pid;
    DIR *proc;
    struct dirent *de;
    int fd;

    /* Also the exact path in the runtime directory just verified: that is what this program
     * exports, and the window passes it on to the clip and migrate it starts. Any other path
     * is refused. */
    if (name != NULL && name[0] == '/' && strncmp(name, rt, rt_len) == 0 && name[rt_len] == '/')
        name += rt_len + 1;
    if (!wayland_name_ok(name))
        die(EX_REFUSED, "WAYLAND_DISPLAY must be a socket name like wayland-1");
    if (!sig_ok(sig))
        die(EX_REFUSED, "HYPRLAND_INSTANCE_SIGNATURE is missing or malformed");

    if (asprintf(&sock_path, "%s/%s", rt, name) < 0)
        die(EX_REFUSED, "out of memory");
    if (lstat(sock_path, &st) != 0 || !S_ISSOCK(st.st_mode) || st.st_uid != ruid)
        die(EX_REFUSED, "%s is not your Wayland socket", sock_path);

    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof addr.sun_path)
        die(EX_REFUSED, "Wayland socket path too long");
    strcpy(addr.sun_path, sock_path);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0)
        die(EX_REFUSED, "cannot connect to %s", sock_path);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
        die(EX_REFUSED, "cannot identify the compositor");
    close(fd);
    if (cred.uid != ruid || !proc_comm_is(cred.pid, comm))
        die(EX_REFUSED, "the compositor behind %s is not your %s", name, comm);

    if (asprintf(&lock_path, "%s/hypr/%s/hyprland.lock", rt, sig) < 0)
        die(EX_REFUSED, "out of memory");
    if (read_small(lock_path, buf, sizeof buf) < 0)
        die(EX_REFUSED, "cannot read %s", lock_path);
    lock_pid = strtol(buf, &line2, 10);
    if (lock_pid != (long)cred.pid || *line2 != '\n')
        die(EX_REFUSED, "the compositor is not the one named by its instance lock");
    line2++;
    line2[strcspn(line2, "\n")] = '\0';
    if (strcmp(line2, name) != 0)
        die(EX_REFUSED, "the instance lock names another Wayland socket");

    if (proc_starttime(cred.pid, &mine) != 0)
        die(EX_REFUSED, "cannot read the compositor's start time");
    proc = opendir("/proc");
    if (proc == NULL)
        die(EX_REFUSED, "cannot read /proc");
    while ((de = readdir(proc)) != NULL) {
        char path[64];
        char *end;
        long pid = strtol(de->d_name, &end, 10);
        if (*end != '\0' || pid <= 0 || pid == (long)cred.pid)
            continue;
        snprintf(path, sizeof path, "/proc/%ld", pid);
        if (stat(path, &st) != 0 || st.st_uid != ruid)
            continue;
        if (!proc_comm_is((pid_t)pid, comm) || proc_starttime((pid_t)pid, &other) != 0)
            continue;
        if (other < mine || (other == mine && pid < (long)cred.pid))
            die(EX_REFUSED, "an older %s of yours is running; refusing a younger one", comm);
    }
    closedir(proc);
    free(lock_path);
    return sock_path;
}

/* Every component of `path`, from the root down, must be owned by owner_uid and (unless it is
 * a symlink, whose mode means nothing) not writable by group or other. Then the same for
 * where it resolves to, so a root-owned symlink cannot lead somewhere you can write. */
static void check_chain_once(const char *path)
{
    char *copy = strdup(path), *slash;
    struct stat st;
    size_t start = strlen(test_root);

    if (copy == NULL)
        die(EX_REFUSED, "out of memory");
    if (copy[0] != '/')
        die(EX_REFUSED, "%s is not absolute", path);
    slash = copy + (start ? start : 0);
    for (;;) {
        char saved;
        slash = strchr(slash + 1, '/');
        if (slash)
            saved = *slash, *slash = '\0';
        if (*copy) {
            if (lstat(copy, &st) != 0)
                die(EX_REFUSED, "%s is missing", copy);
            if (st.st_uid != owner_uid)
                die(EX_REFUSED, "%s is not root-owned", copy);
            if (!S_ISLNK(st.st_mode) && (st.st_mode & (S_IWGRP | S_IWOTH)))
                die(EX_REFUSED, "%s is writable by group or others", copy);
        }
        if (!slash)
            break;
        *slash = saved;
    }
    if (start == 0 && lstat("/", &st) == 0
        && (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH))))
        die(EX_REFUSED, "/ is not root-owned");
    free(copy);
}

static void check_chain(const char *path)
{
    char *real;
    check_chain_once(path);
    real = realpath(path, NULL);
    if (real == NULL)
        die(EX_REFUSED, "cannot resolve %s", path);
    if (*test_root && strncmp(real, test_root, strlen(test_root)) != 0)
        die(EX_REFUSED, "%s resolves outside the test root", path);
    if (strcmp(real, path) != 0)
        check_chain_once(real);
    free(real);
}

static void close_extra_fds(void)
{
    int fd;
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, ~0U, 0U) == 0)
        goto std;
#endif
    for (fd = 3; fd < 65536; fd++)
        close(fd);
std:
    /* stdin, stdout and stderr stay, but must exist: a later open() must never land on 0-2
     * and be mistaken for a pipe the target trusts. */
    for (fd = 0; fd <= 2; fd++)
        if (fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
            int n = open("/dev/null", O_RDWR);
            if (n != fd)
                die(EX_REFUSED, "cannot reopen fd %d", fd);
        }
}

int main(int argc, char **argv)
{
    const char *role;
    const char *module = NULL;
    const char *target_argv[8];
    char *target, *rt, *wayland, *bus;
    const char *dbus;
    struct passwd *pw;
    uid_t ruid = getuid();
    gid_t client_gid;
    extern char **environ;
    char **e;

    if (argc != 2)
        die(EX_USAGE_, "usage: pear-exec ui|clip|migrate|autofill");
    role = argv[1];
    if (strcmp(role, "clip") == 0)
        module = PEAR_TARGET_CLIP_MODULE;
    else if (strcmp(role, "migrate") == 0)
        module = PEAR_TARGET_MIGRATE_MODULE;
    else if (strcmp(role, "autofill") == 0)
        module = PEAR_TARGET_AUTOFILL_MODULE;
    else if (strcmp(role, "ui") != 0)
        die(EX_USAGE_, "unknown role");

#ifdef PEAR_EXEC_TEST_MODE
    test_root = getenv("PEAR_EXEC_TEST_ROOT");
    if (test_root == NULL || test_root[0] != '/')
        die(EX_REFUSED, "test build needs an absolute PEAR_EXEC_TEST_ROOT");
    owner_uid = getuid();
#endif

    check_identity(ruid, &client_gid);
    (void)client_gid;

    pw = getpwuid(ruid);
    if (pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] != '/' || !safe_value(pw->pw_name)
        || strpbrk(pw->pw_dir, "\n=:") != NULL)
        die(EX_REFUSED, "cannot look up your account");

    rt = check_runtime_dir(ruid);
    wayland = check_wayland(rt, ruid);
    if (asprintf(&bus, "unix:path=%s/bus", rt) < 0)
        die(EX_REFUSED, "out of memory");
    dbus = getenv("DBUS_SESSION_BUS_ADDRESS");
    /* The window's own dead address is accepted from the window: a clip or migrate started
     * by it is given the real bus below. */
    if (dbus != NULL && strcmp(dbus, bus) != 0 && strcmp(dbus, PEAR_NO_SESSION_BUS) != 0)
        die(EX_REFUSED, "DBUS_SESSION_BUS_ADDRESS must be %s", bus);

    /* From scratch: who you are, where your session is, and nothing else of yours. */
    env_put("HOME", pw->pw_dir);
    env_put("USER", pw->pw_name);
    env_put("LOGNAME", pw->pw_name);
    env_put("PATH", "/usr/bin");
    env_put("XDG_RUNTIME_DIR", rt);
    env_put("WAYLAND_DISPLAY", wayland);
    env_put("DBUS_SESSION_BUS_ADDRESS", module == NULL ? PEAR_NO_SESSION_BUS : bus);
    pass_if_safe("HYPRLAND_INSTANCE_SIGNATURE");
    pass_if_safe("LANG");
    pass_if_safe("XCURSOR_SIZE");
    for (e = environ; *e; e++) {
        const char *eq = strchr(*e, '=');
        char name[32];
        size_t n, i;
        int ok = 1;
        if (strncmp(*e, "LC_", 3) != 0 || eq == NULL)
            continue;
        n = (size_t)(eq - *e);
        if (n >= sizeof name || n <= 3)
            continue;
        for (i = 3; i < n; i++)
            if (!isupper((unsigned char)(*e)[i]) && (*e)[i] != '_')
                ok = 0;
        if (!ok)
            continue;
        memcpy(name, *e, n);
        name[n] = '\0';
        if (safe_value(eq + 1))
            env_put(name, eq + 1);
    }

    /* Forced: nothing the toolkit would read from your home, no disk cache to plant QML in. */
    env_put("QT_QPA_PLATFORM", "wayland");
    env_put("QT_QPA_PLATFORMTHEME", "");
    env_put("QML_DISABLE_DISK_CACHE", "1");
    env_put("QT_LOGGING_RULES", "*=false");
    /* No primary selection: a drag-select in a notes or setup-key field would otherwise put
     * the text where any program can read it (wl-paste --primary), outside pear-clip's rules.
     * No text-input protocol: an input method would be sent the fields' surrounding text. */
    env_put("QT_WAYLAND_DISABLED_INTERFACES", QT_DISABLED_IFACES);
    env_put("XDG_CONFIG_HOME", PEAR_EMPTY_DIR);
    env_put("XDG_CACHE_HOME", PEAR_EMPTY_DIR);
    env_put("XDG_STATE_HOME", PEAR_EMPTY_DIR);
    env_put("XDG_DATA_HOME", PEAR_EMPTY_DIR);
    env_put("XDG_DATA_DIRS", "/usr/share:/usr/local/share");
    env_put("FONTCONFIG_FILE", PEAR_FONTS_CONF);
    env_put("XCURSOR_PATH", "/usr/share/icons");

    if (module == NULL) {
        target = under_root(PEAR_TARGET_UI);
        check_chain(target);
        check_chain(under_root(PEAR_APP_DIR));
        target_argv[0] = PEAR_TARGET_UI;
        target_argv[1] = "-p";
        target_argv[2] = PEAR_APP_DIR;
        target_argv[3] = NULL;
    } else {
        target = under_root(PEAR_VENV_PYTHON);
        check_chain(under_root(PEAR_VENV));
        check_chain(target);
        target_argv[0] = PEAR_VENV_PYTHON;
        target_argv[1] = "-I";
        target_argv[2] = "-m";
        target_argv[3] = module;
        target_argv[4] = NULL;
    }
    check_chain(under_root(PEAR_FONTS_CONF));
    check_chain(under_root(PEAR_EMPTY_DIR));

    umask(077);
    /* Nothing the target starts can gain privileges; it already has the one it needs. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        die(EX_REFUSED, "cannot set no_new_privs");
    close_extra_fds();

    execve(target, (char *const *)target_argv, envv);
    die(EX_EXECFAIL, "cannot run %s: %s", target, strerror(errno));
    return EX_EXECFAIL;
}
