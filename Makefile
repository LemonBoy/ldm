all:
	gcc ldm.c -g -ludev -pedantic -Wall -Wunused-parameter -Wlong-long -Wconversion -Wimplicit-function-declaration -Wstrict-prototypes -o ldm
install: all
	@cp -f ldm /usr/bin/ldm
	@cp -f ldm.daemon /etc/rc.d/ldm
	@chmod +x /etc/rc.d/ldm

