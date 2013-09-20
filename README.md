l(ightweight) d(evice) m(ounter)
================================
2011-2013 (C) The Lemon Man

A lightweight daemon that mounts usb drives, cds, dvds or floppys
automagically. Made for people that have no desktop-manager with
all the bells and whistles but still want to enjoy automount.
It does mount every device in /media and names them by either
(in order) volume label, volume uuid or device serial or using the
fstab rule for that device, if defined.
Everything in ~30Kb of C code with libudev & libmount as only dependencies.

Callbacks
---------
To execute a script after a device is mounted/unmounted just use `-c` to
point to your script/program (must be +x), it will be executed with the 
action performed (mount/unmount/test) and the mountpoint and filesystem as 
arguments respectively.

Blacklisting
------------
If you don't want ldm to automount a certain device just write a fstab 
entry for it, specifying the `noauto` option.

Alternatively porvide a callback. Before a mount is done, the callback will
be executed with `test` action. When the exit code is not 0, the mount will
not be perfomed.

Install
-------
ldm expects a config file at /etc/ldm.conf which contains your
user uid and gid. Don't be scared, it's just a matter of writing
down 2 lines using your favourite editor.

```
USER_GID=<output of `id -g` ran from your user>
USER_UID=<output of `id -u` ran from your user>
```

That's all, I said it was easy!

RTFM, always.

