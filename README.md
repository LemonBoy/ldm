l(ightweight) d(evice) m(ounter)
================================
2011-2012 (C) The Lemon Man

A lightweight daemon that mounts usb drives, cds, dvds or floppys
automagically. Made for people that have no desktop-manager with
all the bells and whistles but still want to enjoy automount.
It does mount every device in /media and names them by either
(in order) volume label, volume uuid or device serial or using the
fstab rule for that device, if defined.
Everything in ~20Kb of C code with libudev & libmount as only dependencies.

Blacklisting
------------
If you don't want ldm to automount a certain device just slap its uuid into
the blacklist.h and recompile ldm. It's easy as it sounds.

Install
-------
ldm expects a config file at /etc/conf.d/ldm which contains your
user uid and gid. Don't be scared, it's just a matter of writing
down 2 lines using your favourite editor.

```
USER_GID=<output of `id -g` ran from your user>
USER_UID=<output of `id -u` ran from your user>
```

That's all, I said it was easy!

RTFM, always.

