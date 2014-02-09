l(ightweight) d(evice) m(ounter)
================================
2011-2014 (C) The Lemon Man

A lightweight daemon that mounts usb drives, cds, dvds or floppys
automagically. Made for people that have no desktop-manager with
all the bells and whistles but still want to enjoy automount.
It does mount every device in /mnt (but feel free to change the mount path
in the source code) and names them by either (in order) volume label,
volume uuid or device serial or using the fstab rule for that device, if defined.
Everything in ~30Kb of C code with libudev & libmount as only dependencies.

Unmounting
----------
You can unmount a filesystem from the userspace as long as an instance of ldm is
running, just type

```
ldm -r <dev node or mountpoint>
```

in your favourite terminal and you're good to go!

Callbacks
---------
To execute a script after a device is mounted/unmounted just edit ldm.c
and point CALLBACK_PATH to your script/program (must be +x), it will be
executed with the action performed (mount/unmount) and the mountpoint as
arguments respectively.

Blacklisting
------------
If you don't want ldm to automount a certain device just write a fstab
entry for it, specifying the `noauto` option.

Install
-------
ldm honors a config file at /etc/ldm.conf in which you can define your
user ID (UID) and group ID (GID). The default values are set as follows:

```
USER_GID=100
USER_UID=1000
```

To find your user's UID and GID, simply type:

```
$ id -g
100
$ id -u
1000
```

That's all, I said it was easy!

RTFM, always.
