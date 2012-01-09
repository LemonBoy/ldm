all:
	@echo "#define CONFIG_USER_UID " \
		$(shell cat /etc/passwd | \
		grep `who | awk '{print$$1}'` | \
		awk -F':' '{print$$3}') > config.h
	@echo "#define CONFIG_USER_GID " \
		$(shell cat /etc/passwd | \
		grep `who | awk '{print$$1}'` | \
		awk -F':' '{print$$4}') >> config.h
	gcc ldm.c -g -ludev -o ldm
install: all
	@cp -f ldm /usr/bin/ldm
	@cp -f ldm.daemon /etc/rc.d/ldm
	@chmod +x /etc/rc.d/ldm

