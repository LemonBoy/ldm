#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <poll.h>
#include <pwd.h>
#include <libudev.h>
#include <mntent.h>
#include "config.h"

#define VERSION_STR "0.2"

enum {
    DEVICE_VOLUME,
    DEVICE_CD,
    DEVICE_FLOPPY,
    DEVICE_UNK
};

typedef struct fstab_node_t {
    struct fstab_node_t *next;
    char                *node;
    char                *path;
    char                *type;
    char                *opts;
} fstab_node_t;

typedef struct fstab_t {
    struct fstab_node_t *head;
} fstab_t;

typedef struct device_t  {
    int                  type;
    char                *filesystem;
    char                *devnode;
    char                *mountpoint;
    int                  has_media;
    int                  mounted;
    struct udev_device  *udev;
    struct fstab_node_t *fstab_entry;
} device_t;

#define MOUNT_CMD   "/bin/mount -t %s -o %s%s %s %s"
#define ID_FMT      "uid=%i,gid=%i,"
#define UMOUNT_CMD  "/bin/umount %s"
#define MAX_DEVICES 20

/* Static global structs */

static struct fstab_t   * g_fstab;
static struct device_t  * g_devices[MAX_DEVICES];
static FILE             * g_lockfd;
static int                g_running;

/* A less stupid s_strdup */

char *
s_strdup(const char *str)
{
    if (!str)
        return NULL;
    return (char *)strdup(str);
}

/* Locking functions */

#define LOCK_PATH "/var/lock/ldm.lock"

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
lock_remove ()
{
    return (remove(LOCK_PATH) == 0);
}

int
lock_exist ()
{
    FILE *f = fopen(LOCK_PATH, "r");
    if (f)
        fclose(f);
    return (f != NULL);
}

/* fstab handling functions */

#define FSTAB_PATH  "/etc/fstab"
#define MTAB_PATH   "/etc/mtab"

void 
fstab_unload (struct fstab_t *fstab)
{
    struct fstab_node_t *this;
    struct fstab_node_t *next;

    this = fstab->head;

    while (this) {
        next = this->next;
        free(this->node);
        free(this->path);
        free(this->type);
        free(this->opts);
        free(this);
        this = next;
    }
}

struct fstab_node_t *
fstab_search (struct fstab_t *fstab, struct device_t *device)
{
    struct fstab_node_t *node;
    const char *tmp;

    for (node = fstab->head; node; node = node->next) {
        if (!strncasecmp(node->node, "UUID=", 5)) {
            tmp = udev_device_get_property_value(device->udev, "ID_FS_UUID_ENC");
            if (tmp && !strcmp(node->node + 5, tmp))
                return node;
        }

        else if (!strncasecmp(node->node, "LABEL=", 6)) {
            tmp = udev_device_get_property_value(device->udev, "ID_FS_LABEL_ENC");
            if (tmp && !strcmp(node->node + 6, tmp))
                return node;
        }

        else if (!strcmp(node->node, device->devnode))
            return node;
    }
    return NULL;
}

int
fstab_parse (struct fstab_t *fstab)
{
    FILE *f;
    struct mntent *mntent;
    struct fstab_node_t *node;
    struct fstab_node_t *last;

    f = setmntent(FSTAB_PATH, "r");
    if (!f)
        return 0;
    while ((mntent = getmntent(f))) {        
        node = malloc(sizeof(struct fstab_node_t));

        node->next = NULL;
        node->node = s_strdup(mntent->mnt_fsname);
        node->path = s_strdup(mntent->mnt_dir);
        node->type = s_strdup(mntent->mnt_type);
        node->opts = s_strdup(mntent->mnt_opts);

        if (!fstab->head) {
            fstab->head = node;
        } else {
            last = fstab->head;
            while (last->next) {
                last = last->next;
            }
            last->next = node;
        }
    }
    endmntent(f); 
    return 1;
}


int
device_is_mounted (char *node) 
{
    FILE *f;
    struct mntent *mntent;

    f = setmntent(MTAB_PATH, "r");
    if (!f)
        return 0;
    while ((mntent = getmntent(f))) {
        if (!strcmp(mntent->mnt_fsname, node)) {
            endmntent(f);
            return 1;
        }
    }
    endmntent(f);
    return 0;
}

int 
device_has_media (struct device_t *device) 
{
    if (!device)
        return 0;
    switch (device->type) {
        case DEVICE_FLOPPY:
        case DEVICE_VOLUME:
            return (udev_device_get_property_value(device->udev, "ID_FS_USAGE") != NULL);
        break;
        case DEVICE_CD:
            return (udev_device_get_property_value(device->udev, "ID_CDROM_MEDIA") != NULL);
        break;
    }
}

int
filesystem_needs_id_fix (char *fs)
{
    int i;
    static const char *fs_table [] = {
        "msdos", "umsdos", "vfat", "exfat", "ntfs",
    };

    for (i = 0; i < sizeof(fs_table)/sizeof(char*); i++) {
        if (!strcmp(fs_table[i], fs))
            return 1;
    }
    return 0;    
}

char *
device_create_mountpoint (struct device_t *device)
{
    char tmp[256];
    char *name;

    strcpy(tmp, "/media/");

    if (udev_device_get_property_value(device->udev, "ID_FS_LABEL") != NULL)
        strcat(tmp, udev_device_get_property_value(device->udev, "ID_FS_LABEL"));
    else if (udev_device_get_property_value(device->udev, "ID_FS_UUID") != NULL)
        strcat(tmp, udev_device_get_property_value(device->udev, "ID_FS_UUID"));
    else if (udev_device_get_property_value(device->udev, "ID_SERIAL") != NULL)
        strcat(tmp, udev_device_get_property_value(device->udev, "ID_SERIAL"));

    /* Strip the hypen and the subsequent stuff */
    char *hypen = strrchr((const char *)tmp, '-');
    if (hypen)
        *hypen = 0;
    /* Replace the whitespaces */
    char *c;
    for (c = (char*)&tmp; *c; c++) {
       if (*c == ' ')
           *c = '_';
    }

    /* It can't fail as every disc should have at least the serial */

    return s_strdup(tmp);
}

void 
device_list_clear ()
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

    if (j == MAX_DEVICES)
        return;

    if (g_devices[j]->devnode)
        free(g_devices[j]->devnode);
    if (g_devices[j]->filesystem)
        free(g_devices[j]->filesystem);
    if (g_devices[j]->mountpoint)
        free(g_devices[j]->mountpoint);
    udev_device_unref(g_devices[j]->udev);

    free(g_devices[j]);

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

struct device_t *
device_new (struct udev_device *dev)
{
    struct device_t *device;

    const char *dev_type;
    const char *dev_idtype;
   
    device = malloc(sizeof(struct device_t));

    device->udev = dev;

    device->devnode = s_strdup(udev_device_get_devnode(dev));
    device->filesystem = s_strdup(udev_device_get_property_value(dev, "ID_FS_TYPE"));

    dev_type    = udev_device_get_devtype(dev);
    dev_idtype  = udev_device_get_property_value(dev, "ID_TYPE");

    device->type = DEVICE_UNK;

    if (!device->filesystem) {
        device_destroy(device);
        return NULL;
    }

    if ((!strcmp(dev_type, "partition") || !strcmp(dev_type, "disk"))) {
        device->type = DEVICE_VOLUME;
    } else if (!strcmp(dev_idtype, "cd")) {
        device->type = DEVICE_CD;
    } else if (!strcmp(dev_idtype, "floppy")) {
        device->type = DEVICE_FLOPPY;
    }

    if (device->type == DEVICE_UNK) {
        device_destroy(device);
        return NULL;
    }

    device->has_media = device_has_media(device);
    device->fstab_entry = fstab_search(g_fstab, device);

    device->mountpoint = NULL;

    if (device->has_media) {
        if (device->fstab_entry) {
            device->mountpoint = s_strdup(device->fstab_entry->path);
        } else {
            device->mountpoint = device_create_mountpoint(device);
        }
    }

    device->mounted = device_is_mounted(device->devnode);

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
    char cmdline[256];
    char id_fmt[256];
    struct passwd   *user_pwd;
    int needs_mount_id;
 
    device = device_new(dev);

    if (!device)
        return 0;
    
    /* If the device has no media or its already mounted return OK */
    if (!device->has_media || device->mounted)
        return 1;

    mkdir(device->mountpoint, 777);

    /* Microsoft filesystems require the gid and uid to be passed
     * as mount arguments to allow the user to read and write, 
     * while posix filesystems just need a chown after being
     * mounted 
     */
    needs_mount_id = filesystem_needs_id_fix(device->filesystem);

    id_fmt[0] = 0;

    if (needs_mount_id) 
        sprintf(id_fmt, ID_FMT, CONFIG_USER_UID, CONFIG_USER_GID);

    sprintf(cmdline, MOUNT_CMD,
            (device->fstab_entry) ? device->fstab_entry->type : device->filesystem, 
            id_fmt, 
            (device->fstab_entry) ? device->fstab_entry->opts : "defaults", 
            device->devnode, 
            device->mountpoint);

    if (system(cmdline)) {
        syslog(LOG_ERR, "Error while executing mount");
        device_unmount(dev);
        return 0;
    }

    if (!needs_mount_id) {
        if (chown(device->mountpoint, CONFIG_USER_UID, CONFIG_USER_GID)) {
            syslog(LOG_ERR, "Cannot chown the mountpoint");
            device_unmount(dev);
            return 0;
        }
    }

    device->mounted = device_is_mounted(device->devnode);

    return device->mounted;
}

int
device_unmount (struct udev_device *dev)
{
    struct device_t *device;
    char cmdline[256];
    int tries = 10;

    device = device_search((char *)udev_device_get_devnode(dev));

    /* When using eject the remove command is issued 2 times, one when you 
     * execute eject and one when you unplug the device. We already have
     * destroyed the device the first time so the second time it wont find
     * it. So no bitching in the log.                                   */
    if (!device) {
        return 0;
    }

    device->mounted = device_is_mounted(device->devnode);
    if (device->mounted) {
        sprintf(cmdline, UMOUNT_CMD, device->devnode);
        do {
            if (!system(cmdline))
                break;
            sleep(2);
        } while (tries--);
    }

    rmdir(device->mountpoint);

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
    if (!device_new(dev))
        return 0;
    if (!device_mount(dev))
        return 0;

    return 1;
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
    }
    udev_enumerate_unref(udev_enum);
}

void
sig_handler (int signal)
{
    if (signal == SIGINT || signal == SIGTERM)
        g_running = 0;
}

int
daemonize ()
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
        printf("chdir() failed\n");
        return 0;
    }

    umask(0);

    if (setsid() < 0) {
        printf("setsid() failed\n");
        return 0;
    }

    /* Close std* descriptors */
    close(0);
    close(1);
    close(2);

    return 1;
}

int
main (int argc, char **argv)
{
    struct udev         *udev;
    struct udev_monitor *monitor;
    struct udev_device  *device;
    const  char         *action;
    struct pollfd        pollfd;

    printf("ldm "VERSION_STR"\n");
    printf("2011-2012 (C) The Lemon Man\n");

    if (getuid() != 0) {
        printf("You have to run this program as root!\n");
        return 0;
    }

    if (lock_exist()) {
        printf("ldm is already running!\n");
        return 1;
    }

    openlog("ldm", LOG_CONS, LOG_DAEMON);

    if (!daemonize()) {
        printf("Could not spawn the daemon...\n");
        return 0;
    }

    signal(SIGTERM, sig_handler);
    signal(SIGINT , sig_handler);

    syslog(LOG_INFO, "ldm "VERSION_STR);
    syslog(LOG_INFO, "Starting up...");
    
    /* Allocate the head for the fstab LL */
    g_fstab = malloc(sizeof(struct fstab_t));
    g_fstab->head = NULL;

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

    if (!fstab_parse(g_fstab)) {
        syslog(LOG_ERR, "Error while parsing "FSTAB_PATH);
        goto cleanup;
    }

    mount_plugged_devices(udev);

    pollfd.fd       = udev_monitor_get_fd(monitor);
    pollfd.events   = POLLIN;

    syslog(LOG_INFO, "Entering the main loop");

    g_running = 1;

    while (g_running) {
        if (poll(&pollfd, 1, -1) < 1)
            continue;

        if (!(pollfd.revents & POLLIN))
            continue;

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
    }

cleanup:
    /* Do the cleanup */
    udev_monitor_unref(monitor);
    udev_unref(udev);

    device_list_clear();

    fstab_unload(g_fstab);
    free(g_fstab);

    syslog(LOG_INFO,  "Terminating...");
    lock_remove();

    return 1;
}
