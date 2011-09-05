#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libudev.h>
#include <mntent.h>

#define VERSION_STR "0.1"

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

#define MOUNT_CMD   "/bin/mount -t %s -o %s %s %s"
#define UMOUNT_CMD  "/bin/umount %s"
#define MAX_DEVICES 20

/* Static global structs */

static struct fstab_t   * g_fstab;
static struct device_t  * g_devices[MAX_DEVICES];
static FILE             * g_logfd;
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

/* Logging functions */

#define LOG_PATH "/var/log/ldm.log"

int
log_open ()
{
    g_logfd = fopen(LOG_PATH, "a");
    return (g_logfd != 0);
}

void 
log_write (char *category, char *text)
{
    fprintf(g_logfd, "[%i][%s] %s\n", time(NULL), category, text);
    fflush(g_logfd);
}

int
log_close ()
{
    fclose(g_logfd);
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
            tmp = udev_device_get_property_value(device->udev, "ID_FS_UUID_SAFE");
            if (tmp && !strcmp(node->node + 5, tmp))
                return node;
        }

        else if (!strncasecmp(node->node, "LABEL=", 6)) {
            tmp = udev_device_get_property_value(device->udev, "ID_FS_LABEL_SAFE");
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
device_is_mounted (struct device_t *device) 
{
    FILE *f;
    struct mntent *mntent;

    f = setmntent(MTAB_PATH, "r");
    if (!f)
        return 0;
    while ((mntent = getmntent(f))) {
        if (!strcmp(mntent->mnt_fsname, device->devnode)) {
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
    /*struct udev_list_entry *k =  udev_device_get_properties_list_entry(device->udev);
    struct udev_list_entry *y;
    udev_list_entry_foreach(y, k) {
        printf("%s %s\n", udev_list_entry_get_name(y), udev_list_entry_get_value(y));
    }*/

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

char *
device_create_mountpoint (struct device_t *device)
{
    char tmp[256];
    char *name;

    strcpy(tmp, "/media/");

    if (udev_device_get_property_value(device->udev, "ID_FS_LABEL_SAFE") != NULL)
        strcat(tmp, udev_device_get_property_value(device->udev, "ID_FS_LABEL_SAFE"));
    else if (udev_device_get_property_value(device->udev, "ID_FS_UUID_SAFE") != NULL)
        strcat(tmp, udev_device_get_property_value(device->udev, "ID_FS_UUID_SAFE"));
    else if (udev_device_get_property_value(device->udev, "ID_SERIAL") != NULL)
        strcat(tmp, udev_device_get_property_value(device->udev, "ID_SERIAL"));

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

    if (!strcmp(dev_idtype, "disk") &&
        (!strcmp(dev_type, "partition") || !strcmp(dev_type, "disk"))) {
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

    device->mounted = device_is_mounted(device);

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

    device = device_new(dev);

    if (!device)
        return 0;
    
    /* If the device has no media or its already mounted return OK */
    if (!device->has_media || device->mounted)
        return 1;

    mkdir(device->mountpoint, 777);
       
    sprintf(cmdline, MOUNT_CMD, 
            (device->fstab_entry) ? device->fstab_entry->type : device->filesystem, 
            (device->fstab_entry) ? device->fstab_entry->opts : "defaults", 
            device->devnode, 
            device->mountpoint);

    if (system(cmdline) < 0) {
        log_write("ERR", "Error while executing mount");
        return 0;
    }

    device->mounted = device_is_mounted(device);

    return device->mounted;
}

int
device_unmount (struct udev_device *dev)
{
    struct device_t *device;
    char cmdline[256];

    device = device_search((char *)udev_device_get_devnode(dev));

    if (!device) {
        log_write("ERR", "Cannot find the device...unmount halted");
        return 0;
    }

    /* The device isn't mounted, return ok */
    if (!device->mounted)
        return 1;

    sprintf(cmdline, UMOUNT_CMD, device->devnode);

    if (system(cmdline) < 0) {
        log_write("ERR", "Cannot delete the mountpoint");
        return 0;
    }

    sprintf(cmdline, "rm -rf %s", device->mountpoint);
    if (system(cmdline) < 0) {
        log_write("ERR", "Error while executing umount");
        return 0;
    }

    device_destroy(device);
    
    return 1;
}

int 
device_change (struct udev_device *dev)
{
    struct device_t *device;

    device = device_search((char *)udev_device_get_devnode(dev));

    /* Unmount the old media... */
    if (device && device->mounted && !device_unmount(dev)) 
        return 0;
    /* ...and mount the new one if present */    
    if (!device_new(dev))
        return 0;
    if (!device_mount(dev))
        return 0;

    return 1;
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

    printf("ldm "VERSION_STR"\n");
    printf("2011 (C) The Lemon Man\n");

    if (getuid() != 0) {
        printf("You have to run this program as root!\n");
        return 0;
    }

    if (lock_exist()) {
        printf("ldm is already running!\n");
        return 1;
    }

    if (!log_open()) {
        printf("Cannot open the log for writing\nAre you running me as root ?\n");
        return 0;
    }    

    if (!daemonize()) {
        printf("Could not spawn the daemon...\n");
        return 0;
    }

    signal(SIGTERM, sig_handler);
    signal(SIGINT , sig_handler);

    log_write("INFO", "ldm "VERSION_STR);
    log_write("INFO", "Starting up...");

    /* Allocate the head for the fstab LL */
    g_fstab = malloc(sizeof(struct fstab_t));
    g_fstab->head = NULL;

    /* Create the udev struct/monitor */
    udev = udev_new();
    monitor = udev_monitor_new_from_netlink(udev, "udev");

    if (!monitor) {
        log_write("ERR", "Cannot create a new monitor");
        goto cleanup;
    }
    if (udev_monitor_enable_receiving(monitor)) {
        log_write("ERR", "Cannot enable receiving");   
        goto cleanup;
    }
    if (udev_monitor_filter_add_match_subsystem_devtype(monitor, "block", NULL)) {
        log_write("ERR", "Cannot set the filter");
        goto cleanup;
    }

    /* Clear the devices array */
    device_list_clear();

    if (!fstab_parse(g_fstab)) {
        log_write("ERR", "Error while parsing "FSTAB_PATH);
        goto cleanup;
    }

    log_write("INFO", "Entering the main loop");

    g_running = 1;

    while (g_running) {
        device = udev_monitor_receive_device(monitor);

        if (!device)
            continue;

        action = udev_device_get_action(device);    
              
        if (!strcmp(action, "add") && !device_mount(device))
            log_write("ERR", "Error while mounting the device");
        else if (!strcmp(action, "remove") && !device_unmount(device))
            log_write("ERR", "Error while unmounting the device");
        else if (!strcmp(action, "change") && !device_change(device))
            log_write("ERR", "Error while changing the device");
    }

cleanup:
    /* Do the cleanup */
    udev_monitor_unref(monitor);
    udev_unref(udev);

    device_list_clear();

    fstab_unload(g_fstab);
    free(g_fstab);

    log_write("INFO", "Terminating...");
    lock_remove();
    log_close();

    return 1;
}
