#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <poll.h>
#include <libudev.h>
#include <sys/inotify.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <libmount/libmount.h>
#include <errno.h>

#define VERSION_STR "0.4.3"

enum {
    DEVICE_VOLUME,
    DEVICE_CD,
    DEVICE_UNK
};

enum {
    QUIRK_NONE = 0,
    QUIRK_OWNER_FIX = (1<<0),
    QUIRK_UTF8_FLAG = (1<<1),
    QUIRK_MASK = (1<<2),
    QUIRK_FLUSH = (1<<3)
};

typedef struct device_t {
    int kind;
    char *node;
    char *rnode; /* Pointer to the resolved /dev node */
    char *filesystem;
    char *mountpoint;
    struct udev_device *udev;
} device_t;

typedef struct fs_quirk_t {
    char *name;
    int quirks;
} fs_quirk_t;

#define OPT_FMT         "uid=%i,gid=%i"
#define MAX_DEVICES     20
#define FSTAB_PATH      "/etc/fstab"
#define MTAB_PATH       "/proc/self/mounts"
#define LOCK_PATH       "/run/ldm.pid"
#define FIFO_PATH       "/run/ldm.fifo"

/* Static global structs */

static struct libmnt_table *g_fstab;
static struct libmnt_table *g_mtab;
static struct device_t *g_devices[MAX_DEVICES];
static FILE *g_lockfd;
static int g_running;
static int g_gid, g_uid;
static char *g_mount_path;
static char *g_callback_path;

/* A less stupid strdup */

char *
xstrdup(const char *str)
{
    if (!str)
        return NULL;
    return (char *)strdup(str);
}

/* A less stupid strcmp */

int
xstrcmp (const char *s1, const char *s2)
{
    if (!s1 || !s2)
        return 1;
    return strcmp(s1, s2);
}

/* Locking functions */

int
lock_create (int pid)
{
    g_lockfd = fopen(LOCK_PATH, "w+");
    if (!g_lockfd)
        return 0;
    fprintf(g_lockfd, "%d", pid);
    fclose(g_lockfd);
    return 1;
}

/* Spawn helper */

int
spawn_helper (const char *helper, const char *action, char *mountpoint)
{
    pid_t child_pid;
    int ret;

    if (!helper)
        return 0;

    child_pid = fork();

    if (child_pid < 0)
        return 0;

    if (child_pid > 0) {
        wait(&ret);
        /* Return the exit code or 0 if something went wrong */
        return WIFEXITED(ret) ? WEXITSTATUS(ret) : 0;
    }

    /* Drop the root priviledges. Oh and the bass too. */
    setgid(g_gid);
    setuid(g_uid);

    execvp(helper, (char *[]){ (char *)helper, (char *)action, mountpoint, NULL });
    /* Should never reach this */
    syslog(LOG_ERR, "Could not execute \"%s\"", helper);
    /* Die */
    _Exit(1);
}

/* Convenience function for fstab handling */

struct libmnt_fs *
fstab_search (struct libmnt_table *tab, struct udev_device *udev)
{
    struct libmnt_fs *ret;
    char *tmp;
    char keyword[128];

    /* Try matching the /dev/ node */
    tmp = (char *)udev_device_get_devnode(udev);
    ret = mnt_table_find_source(tab, tmp, MNT_ITER_FORWARD);
    if (ret)
        return ret;

    /* Try to resolve the /dev node and retry, this expands the dm-n to the full path */
    tmp = mnt_resolve_path(tmp, NULL);
    if (!tmp)
        return NULL;
    ret = mnt_table_find_source(tab, tmp, MNT_ITER_FORWARD);
    free(tmp);
    if (ret)
        return ret;

    /* Try matching the uuid */
    tmp = (char *)udev_device_get_property_value(udev, "ID_FS_UUID");
    if (!tmp)
        return NULL;
    snprintf(keyword, sizeof(keyword), "UUID=%s", tmp);
    ret = mnt_table_find_source(tab, keyword, MNT_ITER_FORWARD);
    if (ret)
        return ret;

    /* Try matching the label */
    tmp = (char *)udev_device_get_property_value(udev, "ID_FS_LABEL");
    if (!tmp)
        return NULL;
    snprintf(keyword, sizeof(keyword), "LABEL=%s", tmp);
    ret = mnt_table_find_source(tab, keyword, MNT_ITER_FORWARD);
    if (ret)
        return ret;

    return NULL;
}

int
fstab_has_option (struct libmnt_table *tab, struct udev_device *udev, const char *option)
{
    struct libmnt_fs *ret;

    ret = fstab_search(tab, udev);
    if (!ret)
        return 0;

    return mnt_fs_match_options(ret, option);
}

int
device_has_media (struct udev_device *udev, const int dev_kind)
{
    if (!udev)
        return 0;

    switch (dev_kind) {
        case DEVICE_VOLUME:
            return (udev_device_get_property_value(udev, "ID_FS_USAGE") != NULL);
        case DEVICE_CD:
            return (udev_device_get_property_value(udev, "ID_CDROM_MEDIA") != NULL);
        default:
            return 0;
    }
}

int
filesystem_quirks (char *fs)
{
    int i;
    static const fs_quirk_t fs_table [] = {
        { "msdos" , QUIRK_OWNER_FIX | QUIRK_UTF8_FLAG },
        { "umsdos", QUIRK_OWNER_FIX | QUIRK_UTF8_FLAG },
        { "vfat",   QUIRK_OWNER_FIX | QUIRK_UTF8_FLAG | QUIRK_MASK | QUIRK_FLUSH },
        { "exfat",  QUIRK_OWNER_FIX },
        { "ntfs",   QUIRK_OWNER_FIX | QUIRK_UTF8_FLAG | QUIRK_MASK },
        { "iso9660",QUIRK_OWNER_FIX | QUIRK_UTF8_FLAG },
        { "udf",    QUIRK_OWNER_FIX },
    };

    for (i = 0; i < sizeof(fs_table)/sizeof(fs_quirk_t); i++) {
        if (!xstrcmp(fs_table[i].name, fs))
            return fs_table[i].quirks;
    }
    return QUIRK_NONE;
}

char *
device_create_mountpoint (struct device_t *device)
{
    char tmp[PATH_MAX];
    char *c;
    const char *label, *uuid, *serial;

    label = udev_device_get_property_value(device->udev, "ID_FS_LABEL");
    uuid = udev_device_get_property_value(device->udev, "ID_FS_UUID");
    serial = udev_device_get_property_value(device->udev, "ID_SERIAL");

    if (label)
        snprintf(tmp, sizeof(tmp), "%s/%s", g_mount_path, label);
    else if (uuid)
        snprintf(tmp, sizeof(tmp), "%s/%s", g_mount_path, uuid);
    else if (serial)
        snprintf(tmp, sizeof(tmp), "%s/%s", g_mount_path, serial);
    else
        return NULL;

    /* Replace the whitespaces */
    for (c = tmp; *c; c++) {
       if (*c == ' ')
           *c = '_';
    }

    /* Check if there's another folder with the same name */
    while (access(tmp, F_OK) != -1) {
        /* We tried hard and failed */
        if (strlen(tmp) == sizeof(tmp) - 2)
            return NULL;
        /* Append a trailing _ */
        strcat(tmp, "_");
    }

    return xstrdup(tmp);
}

int
device_register (struct device_t *dev)
{
    int j;

    for (j = 0; j < MAX_DEVICES; j++) {
        if (g_devices[j] == NULL) {
            g_devices[j] = dev;
            return 1;
        }
    }

    return 0;
}

void
device_destroy (struct device_t *dev)
{
    int j;

    for (j = 0; j < MAX_DEVICES; j++) {
        if (g_devices[j] == dev)
            break;
    }

    free(dev->node);
    free(dev->rnode);
    free(dev->filesystem);
    free(dev->mountpoint);
    udev_device_unref(dev->udev);

    free(dev);

    /* Might happen that we have to destroy a device not yet
     * registered. Just free it */
    if (j < MAX_DEVICES)
        g_devices[j] = NULL;
}

/* Path is either the /dev/ node or the mountpoint */
struct device_t *
device_search (const char *path)
{
    int j;
    device_t *dev;

    if (!path)
        return NULL;

    for (j = 0; j < MAX_DEVICES; j++) {
        dev = g_devices[j];

        if (dev) {
            if (!xstrcmp(dev->node, path) || !xstrcmp(dev->rnode, path) || !xstrcmp(dev->mountpoint, path))
                return g_devices[j];
        }
    }

    return NULL;
}

int
device_is_mounted (struct udev_device *dev)
{
    /* Use fstab_search to resolve lvm names */
    return (fstab_search(g_mtab, dev) != NULL);
}

struct device_t *
device_new (struct udev_device *dev)
{
    struct device_t *device;
    struct libmnt_fs *fstab_entry;

    const char *dev_node;
    const char *dev_type;
    const char *dev_idtype;
    const char *dev_fs;
    int dev_kind;

    /* First of all check wether we're dealing with a noauto device */
    if (fstab_has_option(g_fstab, dev, "+noauto"))
        return NULL;

    dev_node = udev_device_get_devnode(dev);
    dev_fs = udev_device_get_property_value(dev, "ID_FS_TYPE");

    /* Avoid mounting swap partitions because we're not intrested in those and LVM/LUKS
     * containers as udev issues another event for each single partition contained in them */
    if (!xstrcmp(dev_fs, "swap") || !xstrcmp(dev_fs, "LVM2_member") || !xstrcmp(dev_fs, "crypto_LUKS"))
        return NULL;

    dev_type = udev_device_get_devtype(dev);
    dev_idtype = udev_device_get_property_value(dev, "ID_TYPE");

    if (!xstrcmp(dev_type, "partition") && !xstrcmp(dev_idtype, "disk"))
        dev_kind = DEVICE_VOLUME;
    /* LVM partitions */
    else if (udev_device_get_property_value(dev, "DM_NAME") && !xstrcmp(dev_type, "disk"))
        dev_kind = DEVICE_VOLUME;
    else if (!xstrcmp(dev_idtype, "floppy"))
        dev_kind = DEVICE_VOLUME;
    else if (!xstrcmp(dev_idtype, "cd"))
        dev_kind = DEVICE_CD;
    else
        return NULL;

    if (!device_has_media(dev, dev_kind))
        return NULL;

    device = calloc(1, sizeof(struct device_t));

    if (!device)
        return NULL;

    device->udev = dev;
    device->kind = dev_kind;
    device->node = xstrdup(dev_node);
    device->rnode = mnt_resolve_path(dev_node, NULL);
    device->filesystem = xstrdup(dev_fs);

    /* Increment the refcount */
    udev_device_ref(device->udev);

    fstab_entry = fstab_search(g_fstab, device->udev);

    device->mountpoint = (fstab_entry) ?
        xstrdup(mnt_fs_get_target(fstab_entry)) :
        device_create_mountpoint(device);

    if (!device->mountpoint) {
        syslog(LOG_ERR, "Couldn't make up a mountpoint name. Please report this bug.");
        device_destroy(device);
        return NULL;
    }

    if (!device_register(device)) {
        device_destroy(device);
        return NULL;
    }

    return device;
}

int
device_unmount (struct udev_device *dev)
{
    struct device_t *device;
    struct libmnt_context *ctx;

    device = device_search((char *)udev_device_get_devnode(dev));

    if (!device)
        return 0;

    if (device_is_mounted(dev)) {
        ctx = mnt_new_context();
        mnt_context_set_target(ctx, device->rnode);
        if (mnt_context_umount(ctx)) {
            syslog(LOG_ERR, "Error while unmounting %s (%s)", device->rnode, strerror(errno));
            mnt_free_context(ctx);
            return 0;
        }
        mnt_free_context(ctx);
    }

    rmdir(device->mountpoint);

    spawn_helper(g_callback_path, "unmount", device->mountpoint);

    device_destroy(device);

    return 1;
}

int
device_mount (struct udev_device *dev)
{
    struct device_t *device;
    struct libmnt_context *ctx;
    char opt_fmt[256];
    char *p;
    int quirks;

    device = device_new(dev);

    if (!device)
        return 0;

    mkdir(device->mountpoint, 755);

    p = opt_fmt;

    /* Some filesystems just want to watch the world burn */
    quirks = filesystem_quirks(device->filesystem);

    if (quirks != QUIRK_NONE) {
        /* Microsoft filesystems and filesystems used on optical
         * discs require the gid and uid to be passed as mount
         * arguments to allow the user to read and write, while
         * posix filesystems just need a chown after being mounted */
        if (quirks & QUIRK_OWNER_FIX)
            p += sprintf(p, OPT_FMT",", g_uid, g_gid);
        if (quirks & QUIRK_UTF8_FLAG)
            p += sprintf(p, "utf8,");
        if (quirks & QUIRK_FLUSH)
            p += sprintf(p, "flush,");
        if (quirks & QUIRK_MASK)
            p += sprintf(p, "dmask=022,fmask=133,");
    }
    *p = 0;

    ctx = mnt_new_context();

    mnt_context_set_fstype(ctx, device->filesystem);
    mnt_context_set_source(ctx, device->rnode);
    mnt_context_set_target(ctx, device->mountpoint);
    mnt_context_set_options(ctx, opt_fmt);

    if (device->kind == DEVICE_CD)
        mnt_context_set_mflags(ctx, MS_RDONLY);

    if (mnt_context_mount(ctx)) {
        syslog(LOG_ERR, "Error while mounting %s (%s)", device->rnode, strerror(errno));
        mnt_free_context(ctx);
        device_unmount(dev);
        return 0;
    }

    mnt_free_context(ctx);

    if (!(quirks & QUIRK_OWNER_FIX)) {
        if (chown(device->mountpoint, (__uid_t)g_uid, (__gid_t)g_gid)) {
            syslog(LOG_ERR, "Cannot chown %s", device->mountpoint);
            device_unmount(dev);
            return 0;
        }
    }

    spawn_helper(g_callback_path, "mount", device->mountpoint);

    return 1;
}

int
device_change (struct udev_device *dev)
{
    struct device_t *device;
    const char *id_type;

    device = device_search((char *)udev_device_get_devnode(dev));

    id_type = udev_device_get_property_value(dev, "ID_TYPE");

    /* Handle change events for CD drives only */
    if (xstrcmp(id_type, "cd"))
        return 0;

    if (device) {
        /* Unmount the old media */
        if (device_is_mounted(dev) && !device_unmount(dev))
            return 0;
    }

    /* ...and mount the new one if present */
    if (!device_mount(dev))
        return 0;

    return 1;
}

/* Strip the trailing slash. Brutally. */
#define strip_slash(s) do { size_t l = strlen(s); if (l && s[l-1] == '/') s[l-1] = '\0'; } while(0)

void
handle_ipc_event (char *msg)
{
    struct device_t *device;

    /* Keep it simple */
    switch (msg[0]) {
        case 'R': /* R for Remove */
            strip_slash(msg);

            device = device_search(msg + 1);

            if (device && device_is_mounted(device->udev))
                device_unmount(device->udev);

            break;
    }
}

void
check_registered_devices (void)
{
    int j;

    /* Drop all the devices in the table that aren't mounted anymore */
    for (j = 0; j < MAX_DEVICES; j++) {
        if (g_devices[j] && !device_is_mounted(g_devices[j]->udev))
            device_unmount(g_devices[j]->udev);
    }

}

void
device_list_clear (void)
{
    int j;

    for (j = 0; j < MAX_DEVICES; j++) {
        if (g_devices[j])
            device_unmount(g_devices[j]->udev);
        g_devices[j] = NULL;
    }
}

void
mount_plugged_devices (struct udev *udev)
{
    const char *path;
    struct udev_enumerate *udev_enum;
    struct udev_list_entry *devices;
    struct udev_list_entry *entry;
    struct udev_device *dev;

    udev_enum = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(udev_enum, "block");
    udev_enumerate_scan_devices(udev_enum);
    devices = udev_enumerate_get_list_entry(udev_enum);

    udev_list_entry_foreach(entry, devices) {
        path = udev_list_entry_get_name(entry);
        dev = udev_device_new_from_syspath(udev, path);

        if (!device_is_mounted(dev))
            device_mount(dev);
        udev_device_unref(dev);
    }
    udev_enumerate_unref(udev_enum);
}

struct libmnt_table *
update_mnt_table (const char *path, struct libmnt_table *old)
{
    if (old)
        mnt_free_table(old);
    return mnt_new_table_from_file(path);
}

void
sig_handler (int signal)
{
    if (signal == SIGINT || signal == SIGTERM || signal == SIGHUP)
        g_running = 0;
}

int
daemonize (void)
{
    pid_t child_pid;

    child_pid = fork();

    if (child_pid < 0)
        return 0;

    if (child_pid > 0)
        exit(EXIT_SUCCESS);

    if (chdir("/") < 0) {
        perror("chdir");
        return 0;
    }

    umask(022);

    if (setsid() < 0) {
        perror("setsid");
        return 0;
    }

    /* Close std* descriptors */
    close(0);
    close(1);
    close(2);

    return 1;
}

int
isdir (const char *path)
{
    struct stat st;

    if (stat(path, &st) < 0) 
        return 0;

    return S_ISDIR(st.st_mode);
}

int
fifo_open (int oldfd, const int mode)
{
    int fd;

    if (oldfd > 0)
        close(oldfd);

    if ((fd = open(FIFO_PATH, mode)) < 0) {
        perror("open");
        return -1;
    }

    return fd;
}

int
main (int argc, char *argv[])
{
    struct udev         *udev;
    struct udev_monitor *monitor;
    struct udev_device  *device;
    const  char         *action;
    struct pollfd        pollfd[4];  /* udev / inotify watch / mtab / fifo */
    int                  opt;
    int                  daemon;
    int                  notifyfd;
    int                  watchd;
    int                  ipcfd;
    struct inotify_event event;

    daemon  =  0;
    g_uid   = -1;
    g_gid   = -1;
    watchd  = -1;

    while ((opt = getopt(argc, argv, "hdg:u:r:p:c:")) != -1) {
        switch (opt) {
            case 'r':
                ipcfd = fifo_open(-1, O_WRONLY);
                /* Could not open the pipe */
                if (ipcfd < 0)
                    return EXIT_FAILURE;

                write(ipcfd, "R", 1);
                write(ipcfd, optarg, strlen(optarg));
                close(ipcfd);

                return EXIT_SUCCESS;
            case 'd':
                daemon = 1;
                break;
            case 'g':
                g_gid = (int)strtoul(optarg, NULL, 10);
                break;
            case 'u':
                g_uid = (int)strtoul(optarg, NULL, 10);
                break;
            case 'p':
                g_mount_path = xstrdup(optarg);
                break;
            case 'c':
                if (access(optarg, F_OK | X_OK) < 0)
                    fprintf(stderr, "Callback script not found or not executable\n");
                else
                    g_callback_path = xstrdup(optarg);
            case 'h':
                printf("ldm "VERSION_STR"\n");
                printf("2011-2014 (C) The Lemon Man\n");
                printf("%s [-d | -r | -g | -u | -p | -c | -h]\n", argv[0]);
                printf("\t-d Run ldm as a daemon\n");
                printf("\t-r Removes a mounted device\n");
                printf("\t-g Specify the gid\n");
                printf("\t-u Specify the gid\n");
                printf("\t-p Specify where to mount the devices\n");
                printf("\t-c Specify the path to the script executed after mount/unmount events\n");
                printf("\t-h Show this help\n");
                /* Falltrough */
            default:
                return EXIT_SUCCESS;
        }
    }

    if (g_uid < 0 || g_gid < 0) {
        fprintf(stderr, "You must supply your gid/uid!\n");
        return EXIT_FAILURE;
    }

    /* A not-so-safe default */
    if (!g_mount_path)
        g_mount_path = xstrdup("/mnt");

    /* Check anyways */
    if (!isdir(g_mount_path)) {
        fprintf(stderr, "The path %s doesn't name a folder or doesn't exist!\n", g_mount_path);

        free(g_callback_path);
        free(g_mount_path);

        return EXIT_FAILURE;
    }

    /* Sanitize before use */
    strip_slash(g_mount_path);

    if (getuid() != 0) {
        fprintf(stderr, "You have to run this program as root!\n");
        return EXIT_FAILURE;
    }

    if (access(LOCK_PATH, F_OK) != -1) {
        fprintf(stderr, "ldm is already running!\n");
        return EXIT_SUCCESS;
    }

    notifyfd = inotify_init();

    if (notifyfd < 0) {
        perror("inotify_init");
        return EXIT_FAILURE;
    }

    /* Create the ipc socket */
    unlink(FIFO_PATH);
    umask(0);

    if (mkfifo(FIFO_PATH, 0666) < 0) {
        perror("mkfifo");
        return EXIT_FAILURE;
    }

    ipcfd = fifo_open(-1, O_RDONLY | O_NONBLOCK);

    if (ipcfd < 0)
        return EXIT_FAILURE;

    if (daemon && !daemonize()) {
        fprintf(stderr, "Could not spawn the daemon!\n");
        return EXIT_FAILURE;
    }

    lock_create(getpid());

    openlog("ldm", LOG_CONS, LOG_DAEMON);

    signal(SIGTERM, sig_handler);
    signal(SIGINT , sig_handler);
    signal(SIGHUP , sig_handler);

    syslog(LOG_INFO, "ldm "VERSION_STR);
    syslog(LOG_INFO, "Starting up...");

    /* Create the udev struct/monitor */
    udev = udev_new();
    monitor = udev_monitor_new_from_netlink(udev, "udev");

    if (!monitor) {
        syslog(LOG_ERR, "Cannot create a new monitor");
        goto cleanup;
    }
    if (udev_monitor_enable_receiving(monitor)) {
        syslog(LOG_ERR, "Cannot enable receiving");
        goto cleanup;
    }
    if (udev_monitor_filter_add_match_subsystem_devtype(monitor, "block", NULL)) {
        syslog(LOG_ERR, "Cannot set the filter");
        goto cleanup;
    }

    /* Clear the devices array */
    device_list_clear();

    g_fstab = NULL;
    g_mtab  = NULL;

    /* The loop isn't active at this time so just do it by hand */
    if (!(g_fstab = update_mnt_table(FSTAB_PATH, g_fstab)))
        goto cleanup;

    if (!(g_mtab = update_mnt_table(MTAB_PATH, g_mtab)))
        goto cleanup;

    mount_plugged_devices(udev);

    if (!(g_fstab = update_mnt_table(FSTAB_PATH, g_fstab)))
        goto cleanup;

    if (!(g_mtab = update_mnt_table(MTAB_PATH, g_mtab)))
        goto cleanup;

    watchd = inotify_add_watch(notifyfd, FSTAB_PATH, IN_CLOSE_WRITE);

    /* Register all the events */
    pollfd[0].fd = udev_monitor_get_fd(monitor);
    pollfd[0].events = POLLIN;
    pollfd[1].fd = notifyfd;
    pollfd[1].events = POLLIN;
    pollfd[2].fd = open(MTAB_PATH, O_RDONLY | O_NONBLOCK);
    pollfd[2].events = POLLERR;
    pollfd[3].fd = ipcfd;
    pollfd[3].events = POLLIN;

    syslog(LOG_INFO, "Entering the main loop");

    g_running = 1;

    while (g_running) {
        if (poll(pollfd, 4, -1) < 1)
            continue;

        /* Incoming message on udev socket */
        if (pollfd[0].revents & POLLIN) {
            device = udev_monitor_receive_device(monitor);

            if (!device)
                continue;

            action = udev_device_get_action(device);

            if (!xstrcmp(action, "add"))
                device_mount(device);
            else if (!xstrcmp(action, "remove"))
                device_unmount(device);
            else if (!xstrcmp(action, "change"))
                device_change(device);

            udev_device_unref(device);
        }
        /* Incoming message on inotify socket */
        if (pollfd[1].revents & POLLIN) {
            read(pollfd[1].fd, &event, sizeof(struct inotify_event));

            if (mnt_table_parse_fstab(g_fstab, NULL) < 0)
                break;
        }
        /* mtab change */
        if (pollfd[2].revents & POLLERR) {
            read(pollfd[2].fd, &event, sizeof(struct inotify_event));

            if (!(g_mtab = update_mnt_table(MTAB_PATH, g_mtab)))
                break;

            check_registered_devices();
        }
        /* ipc message on the fifo */
        if (pollfd[3].revents & POLLIN) {
            int msg_len;
            /* Get the exact message length */
            if (ioctl(ipcfd, FIONREAD, &msg_len) < 0) {
                syslog(LOG_ERR, "ipc:ioctl(FIONREAD) failed!");
                break;
            }

            char msg[msg_len];
            if (read(ipcfd, msg, msg_len) != msg_len) {
                syslog(LOG_ERR, "ipc:read() failed!");
                break;
            }
            msg[msg_len] = '\0';

            handle_ipc_event(msg);

            /* The fifo is closed once the other end finishes sending the data so just reopen it. */
            pollfd[3].fd = ipcfd = fifo_open(ipcfd, O_RDONLY | O_NONBLOCK);
        }
    }

cleanup:
    free(g_callback_path);
    free(g_mount_path);

    /* Do the cleanup */
    inotify_rm_watch(notifyfd, watchd);

    close(ipcfd);
    close(notifyfd);
    close(pollfd[2].fd);

    unlink(FIFO_PATH);
    unlink(LOCK_PATH);

    device_list_clear();

    udev_monitor_unref(monitor);
    udev_unref(udev);

    mnt_free_table(g_fstab);
    mnt_free_table(g_mtab);

    syslog(LOG_INFO, "Terminating...");

    return EXIT_SUCCESS;
}
