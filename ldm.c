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
#include <libmount/libmount.h>
#include <errno.h>

#define VERSION_STR "0.4.2"

enum {
    DEVICE_VOLUME,
    DEVICE_CD,
    DEVICE_UNK
};

enum {
    QUIRK_NONE = 0,
    QUIRK_OWNER_FIX = (1<<0),
    QUIRK_UTF8_FLAG = (1<<1)
};

typedef struct device_t  {
    int                  type;
    char                *filesystem;
    char                *devnode;
    char                *mountpoint;
    struct udev_device  *udev;
} device_t;

typedef struct fs_quirk_t {
    char *name;
    int quirks;
} fs_quirk_t;

#define MOUNT_PATH      "/mnt/"
#define CALLBACK_PATH   NULL
#define OPT_FMT         "uid=%i,gid=%i"
#define MAX_DEVICES     20

/* Static global structs */

static struct libmnt_table     *g_fstab;
static struct libmnt_table     *g_mtab;
static struct device_t         *g_devices[MAX_DEVICES];
static FILE                    *g_lockfd;
static int                      g_running;
static int                      g_uid;
static int                      g_gid;

/* Functions declaration */
char * s_strdup(const char *str);
int lock_create(int pid);
int lock_remove(void);
int lock_exist(void);
struct libmnt_fs * fstab_search (struct libmnt_table *tab, struct udev_device *device);
int device_has_media(struct device_t *device);
int filesystem_needs_id_fix(char *fs);
char * device_create_mountpoint(struct device_t *device);
void device_list_clear(void);
int device_register(struct device_t *dev);
void device_destroy(struct device_t *dev);
struct device_t * device_search(char *devnode);
struct device_t * device_new(struct udev_device *dev);
int device_mount(struct udev_device *dev);
int device_unmount(struct udev_device *dev);
int device_change(struct udev_device *dev);
int force_reload_table (struct libmnt_table **table, const char *path);
void mount_plugged_devices(struct udev *udev);
void sig_handler(int signal);
int daemonize(void);

/* A less stupid s_strdup */

char *
s_strdup(const char *str)
{
    if (!str)
        return NULL;
    return (char *)strdup(str);
}

/* Locking functions */

#define LOCK_PATH "/run/ldm.pid"

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

int
lock_remove (void)
{
    return (remove(LOCK_PATH) == 0);
}

int
lock_exist (void)
{
    FILE *f = fopen(LOCK_PATH, "r");
    if (f)
        fclose(f);
    return (f != NULL);
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

    return 0xdeadbeef;
}

/* Convenience function for fstab handling */

#define FSTAB_PATH  "/etc/fstab"
#define MTAB_PATH   "/proc/self/mounts"

struct libmnt_fs *
fstab_search (struct libmnt_table *tab, struct udev_device *udev)
{
    struct libmnt_fs *ret;
    const char *tmp;

    /* Try matching the /dev node */
    tmp = udev_device_get_devnode(udev);
    ret = mnt_table_find_source(tab, tmp? tmp: "", MNT_ITER_FORWARD);
    if (ret) return ret;
    /* Try matching the uuid */
    tmp = udev_device_get_property_value(udev, "ID_FS_UUID");
    ret = mnt_table_find_tag(tab, "UUID", tmp? tmp: "", MNT_ITER_FORWARD);
    if (tmp && ret) return ret;
    /* Try matching the label */
    tmp = udev_device_get_property_value(udev, "ID_FS_LABEL");
    ret = mnt_table_find_tag(tab, "LABEL", tmp? tmp: "", MNT_ITER_FORWARD);
    if (tmp && ret) return ret;

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
device_has_media (struct device_t *device) 
{
    if (!device)
        return 0;
    switch (device->type) {
        case DEVICE_VOLUME:
            return (udev_device_get_property_value(device->udev, "ID_FS_USAGE") != NULL);
        case DEVICE_CD:
            return (udev_device_get_property_value(device->udev, "ID_CDROM_MEDIA") != NULL);
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
        { "vfat",   QUIRK_OWNER_FIX | QUIRK_UTF8_FLAG },
        { "exfat",  QUIRK_OWNER_FIX | QUIRK_UTF8_FLAG },
        { "ntfs",   QUIRK_OWNER_FIX | QUIRK_UTF8_FLAG },
        { "iso9660",QUIRK_OWNER_FIX | QUIRK_UTF8_FLAG },
        { "udf",    QUIRK_OWNER_FIX },
    };

    for (i = 0; i < sizeof(fs_table)/sizeof(fs_quirk_t); i++) {
        if (!strcmp(fs_table[i].name, fs))
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
    struct stat st;

    label = udev_device_get_property_value(device->udev, "ID_FS_LABEL");
    uuid = udev_device_get_property_value(device->udev, "ID_FS_UUID");
    serial = udev_device_get_property_value(device->udev, "ID_SERIAL");

    if (label)
        snprintf(tmp, sizeof(tmp), "%s%s", MOUNT_PATH, label);
    else if (uuid)
        snprintf(tmp, sizeof(tmp), "%s%s", MOUNT_PATH, uuid);
    else if (serial)
        snprintf(tmp, sizeof(tmp), "%s%s", MOUNT_PATH, serial);
    else
        return NULL;

    /* Replace the whitespaces */
    for (c = tmp; *c; c++) {
       if (*c == ' ')
           *c = '_';
    }

    /* Check if there's another folder with the same name */
    while (!stat(tmp, &st)) {
        /* We tried hard and failed */
        if (strlen(tmp) == sizeof(tmp) - 2) 
            return NULL;
        /* Append a trailing _ */
        strcat(tmp, "_");
    }

    return s_strdup(tmp);
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

    free(dev->devnode);
    free(dev->filesystem);
    free(dev->mountpoint);
    udev_device_unref(dev->udev);

    free(dev);

    /* Might happen that we have to destroy a device not yet
     * registered. Just free it */
    if (j < MAX_DEVICES)
        g_devices[j] = NULL;
}

struct device_t *
device_search (char *devnode)
{
    int j;

    if (!devnode)
        return NULL;

    for (j = 0; j < MAX_DEVICES; j++) {
        if (g_devices[j] && !strcmp(g_devices[j]->devnode, devnode))
            return g_devices[j];
    }

    return NULL;
}

int
device_is_mounted (char *node)
{
    return (mnt_table_find_source(g_mtab, node, MNT_ITER_FORWARD) != NULL);
}

struct device_t *
device_new (struct udev_device *dev)
{
    struct device_t *device;
    struct libmnt_fs *fstab_entry;

    const char *dev_type;
    const char *dev_idtype;
   
    /* First of all check wether we're dealing with a noauto device */
    if (fstab_has_option(g_fstab, dev, "+noauto")) 
        return NULL;

    device = calloc(1, sizeof(struct device_t));

    if (!device)
        return NULL;

    device->udev = dev;
    udev_device_ref(device->udev);

    device->devnode = s_strdup(udev_device_get_devnode(dev));
    device->filesystem = s_strdup(udev_device_get_property_value(dev, "ID_FS_TYPE"));

    dev_type    = udev_device_get_devtype(dev);
    dev_idtype  = udev_device_get_property_value(dev, "ID_TYPE");

    device->type = DEVICE_UNK;

    if (!device->filesystem || !strcmp(device->filesystem, "swap")) {
        device_destroy(device);
        return NULL;
    }

    if (!strcmp(dev_type,   "partition")|| 
        !strcmp(dev_type,   "disk")     || 
        !strcmp(dev_idtype, "floppy"))  {
        device->type = DEVICE_VOLUME;
    } 
        
    if (dev_idtype && !strcmp(dev_idtype, "cd")) 
        device->type = DEVICE_CD;

    if (device->type == DEVICE_UNK) {
        device_destroy(device);
        return NULL;
    }

    fstab_entry = fstab_search(g_fstab, device->udev);

    if (!device_has_media(device)) {
        device_destroy(device);
        return NULL;
    }

    if (fstab_entry) {
        device->mountpoint = s_strdup(mnt_fs_get_target(fstab_entry));
    } else {
        device->mountpoint = device_create_mountpoint(device);
    }

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
    }
    *p = 0;

    ctx = mnt_new_context();

    mnt_context_set_fstype(ctx, device->filesystem);
    mnt_context_set_source(ctx, device->devnode);
    mnt_context_set_target(ctx, device->mountpoint);
    mnt_context_set_options(ctx, opt_fmt);

    if (device->type == DEVICE_CD) 
        mnt_context_set_mflags(ctx, MS_RDONLY);

    if (mnt_context_mount(ctx)) {
        syslog(LOG_ERR, "Error while mounting %s (%s)", device->devnode, strerror(errno));
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

    spawn_helper(CALLBACK_PATH, "mount", device->mountpoint);

    return 1;
}

int
device_unmount (struct udev_device *dev)
{
    struct device_t *device;
    struct libmnt_context *ctx;

    device = device_search((char *)udev_device_get_devnode(dev));

    if (!device) 
        return 0;

    if (device_is_mounted(device->devnode)) {
        ctx = mnt_new_context();
        mnt_context_set_target(ctx, device->devnode);
        if (mnt_context_umount(ctx)) {
            syslog(LOG_ERR, "Error while unmounting %s (%s)", device->devnode, strerror(errno));
            mnt_free_context(ctx);
            return 0;
        }
        mnt_free_context(ctx);
    }

    rmdir(device->mountpoint);

    spawn_helper(CALLBACK_PATH, "unmount", device->mountpoint);

    device_destroy(device);
    
    return 1;
}

int 
device_change (struct udev_device *dev)
{
    struct device_t *device;

    device = device_search((char *)udev_device_get_devnode(dev));

    /* Unmount the old media... */
    if (device) {
        if (device_is_mounted(device->devnode) && !device_unmount(dev)) 
            return 0;
    }
    /* ...and mount the new one if present */    
    if (!device_mount(dev))
        return 0;

    return 1;
}

void
check_registered_devices (void)
{
    int j;

    /* Drop all the devices in the table that aren't mounted anymore */
    for (j = 0; j < MAX_DEVICES; j++) {
        if (g_devices[j] && !device_is_mounted(g_devices[j]->devnode))
            device_unmount(g_devices[j]->udev);
    }

}

void
mount_plugged_devices (struct udev *udev)
{    
    const char *path;
    const char *dev_node;
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
        dev_node = udev_device_get_devnode(dev);

        if (!device_is_mounted((char *)dev_node))
            device_mount(dev);
        udev_device_unref(dev);
    }
    udev_enumerate_unref(udev_enum);
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

    /* The parent writes the lock then exits */
    if (child_pid > 0) {
        lock_create(child_pid);
        exit(0);
    }

    if (chdir("/") < 0) {
        fprintf(stderr, "chdir() failed\n");
        return 0;
    }

    umask(022);

    if (setsid() < 0) {
        fprintf(stderr, "setsid() failed\n");
        return 0;
    }

    /* Close std* descriptors */
    close(0);
    close(1);
    close(2);

    return 1;
}

int 
force_reload_table (struct libmnt_table **table, const char *path)
{
    if (table && *table)
        mnt_free_table(*table);

    *table = mnt_new_table_from_file(path);

    if (!*table)
        syslog(LOG_ERR, "Error while parsing "FSTAB_PATH);

    return (*table != NULL);
}

int
main (int argc, char *argv[])
{
    struct udev         *udev;
    struct udev_monitor *monitor;
    struct udev_device  *device;
    const  char         *action;
    struct pollfd        pollfd[3];  /* udev / inotify watch / mtab */
    int                  opt;
    int                  daemon;
    int                  notifyfd;
    int                  fswatch;
    struct inotify_event event;

    printf("ldm "VERSION_STR"\n");
    printf("2011-2013 (C) The Lemon Man\n");

    if (getuid() != 0) {
        printf("You have to run this program as root!\n");
        return 1;
    }

    if (lock_exist()) {
        printf("ldm is already running!\n");
        return 0;
    }

    notifyfd = inotify_init();

    if (notifyfd < 0) {
        printf("Could not initialize inotify\n");
        return 0;
    }

    daemon  =  0;
    g_uid   = -1;
    g_gid   = -1;
    fswatch = -1;

    while ((opt = getopt(argc, argv, "dg:u:")) != -1) {
        switch (opt) {
            case 'd':
                daemon = 1;
                break;
            case 'g':
                g_gid = (int)strtoul(optarg, NULL, 10);
                break;
            case 'u':
                g_uid = (int)strtoul(optarg, NULL, 10);
                break;
            default:
                return 1;
        }
    }

    if (g_uid < 0 || g_gid < 0) {
        printf("You must supply your gid/uid!\n");
        return 1;
    }

    openlog("ldm", LOG_CONS, LOG_DAEMON);

    if (daemon && !daemonize()) {
        printf("Could not spawn the daemon...\n");
        return 1;
    }

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
    if (!force_reload_table(&g_fstab, FSTAB_PATH) || !force_reload_table(&g_mtab, MTAB_PATH))
        goto cleanup;

    mount_plugged_devices(udev);

    if (!force_reload_table(&g_fstab, FSTAB_PATH) || !force_reload_table(&g_mtab, MTAB_PATH))
        goto cleanup;
    
    fswatch = inotify_add_watch(notifyfd, FSTAB_PATH, IN_CLOSE_WRITE);

    /* Register all the events */
    pollfd[0].fd = udev_monitor_get_fd(monitor);
    pollfd[0].events = POLLIN;
    pollfd[1].fd = notifyfd;
    pollfd[1].events = POLLIN;
    pollfd[2].fd = open(MTAB_PATH, O_RDONLY);
    pollfd[2].events = POLLERR;

    syslog(LOG_INFO, "Entering the main loop");

    g_running = 1;

    while (g_running) {
        if (poll(pollfd, 3, -1) < 1)
            continue;

        /* Incoming message on udev socket */
        if (pollfd[0].revents & POLLIN) {
            device = udev_monitor_receive_device(monitor);

            if (!device)
                continue;

            action = udev_device_get_action(device);    

            if (!strcmp(action, "add"))
                device_mount(device);
            else if (!strcmp(action, "remove"))
                device_unmount(device);
            else if (!strcmp(action, "change"))
                device_change(device);

            udev_device_unref(device);
        }
        /* Incoming message on inotify socket */
        if (pollfd[1].revents & POLLIN) {
            read(pollfd[1].fd, &event, sizeof(struct inotify_event)); 

            if (!force_reload_table(&g_fstab, FSTAB_PATH))
                goto cleanup;
        }
        /* mtab change */
        if (pollfd[2].revents & POLLERR) {
            if (!force_reload_table(&g_mtab, MTAB_PATH))
                goto cleanup;
            check_registered_devices();
        }
    }

cleanup:
    /* Do the cleanup */
    if (fswatch > 0)
        inotify_rm_watch(notifyfd, fswatch);

    close(notifyfd);
    close(pollfd[2].fd);

    device_list_clear();

    udev_monitor_unref(monitor);
    udev_unref(udev);

    mnt_free_table(g_fstab);
    mnt_free_table(g_mtab);

    syslog(LOG_INFO,  "Terminating...");
    lock_remove();

    return 0;
}
