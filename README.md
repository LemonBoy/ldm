# NAME

ldm - Lightweight Device Mounter

# SYNOPSIS

_ldm_ \[-d\] \[-u _user_\] \[-p _path_\] \[-c _command_\] \[-m _mask_\] \[-h\]

# DESCRIPTION

ldm is a lightweight device mounter following the UNIX philosophy written in C and based on udev and libmount.
The user can use **umount** to unmount the device or **ldmc** with the **-r** switch.
The daemon can be controlled with the **ldmc** tool.

# OPTIONS

- **-d**

    Run ldm as a daemon.

- **-u** _user_

    Specify the user who owns the mountpoints.

- **-p** _path_

    Specify the base folder for the mount points. The default is /mnt.

- **-m** _fmask_,_dmask_

    Specify the fmask and dmask for the mounted devices in octal or symbolic format (eg. the octal mask
    0777 is represented as rwxrwxrwx).

    If only the _fmask_ is specified then its used as umask and it's
    value is used as dmask too.

- **-c** _command_

    Specifies a command that is executed after a successful mount/unmount action. The following environment variables are defined :

    - **LDM\_MOUNTPOINT**

        The complete path to the mountpoint.

    - **LDM\_NODE**

        The path pointing to the device node in /dev

    - **LDM\_FS**

        The filesystem on the mounted device.

    - **LDM\_ACTION**

        The action ldm has just performed, it can either be _mount_, _pre\_unmount_ or _unmount_

- **-h**

    Print a brief help and exit.

# BLACKLISTING

ldm doesn't offer any blacklisting by itself but it honors the options found in the fstab so it will ignore any device with flag _noauto_.

# INSTALL

The included systemd service expects a config file at /etc/ldm.conf similar to this:

<div>
    <pre>
    <code>
    MOUNT_OWNER=<i>username</i>
    BASE_MOUNTPOINT=<i>/mnt</i>
    FMASK_DMASK=<i>fmask,dmask</i>
    EXTRA_ARGS=<i>-c &lt;path_to_executable&gt;</i>
    </code>
    </pre>
</div>

The options **FMASK\_DMASK** and **EXTRA\_ARGS** are optional.
The default value for **FMASK\_DMASK** is _0133,0022_.
**EXTRA\_ARGS** will be appended to the _ldm_ executable.

# SEE ALSO

ldmc(1), umount(8)

# WWW

[git repository](https://github.com/LemonBoy/ldm)

# AUTHOR

2011-2019 (C) The Lemon Man <thatlemon@gmail.com>
