all:
	gcc ldm.c -ludev -o ldm
install: all
	@cp -f ldm /usr/bin/ldm
	@cp -f ldm.daemon /etc/rc.d/ldm
	@chmod +x /etc/rc.d/ldm

