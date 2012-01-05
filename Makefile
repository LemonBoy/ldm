all:
	@echo "#define CONFIG_USER_UID " $(shell id -u $(w -h | awk '{print$1}')) > config.h
	@echo "#define CONFIG_USER_GID " $(shell id -g $(w -h | awk '{print$1}')) >> config.h
	gcc ldm.c -g -ludev -o ldm
install: all
	@cp -f ldm /usr/bin/ldm
	@cp -f ldm.daemon /etc/rc.d/ldm
	@chmod +x /etc/rc.d/ldm

