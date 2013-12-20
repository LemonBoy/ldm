CC	?= gcc
CFLAGS ?= -O2
LDFLAGS += -ludev -lmount
CFDEBUG = -g3 -pedantic -Wall -Wunused-parameter -Wlong-long\
		  -Wsign-conversion -Wconversion -Wimplicit-function-declaration

EXEC = ldm
SRCS = ldm.c
OBJS = ${SRCS:.c=.o}

PREFIX?=/usr
BINDIR=${PREFIX}/bin
SYSTEMDDIR=/usr/lib/systemd/system

all: ${EXEC}

.c.o:
	${CC} ${CFLAGS} -o $@ -c $<

${EXEC}: ${OBJS}
	${CC} ${LDFLAGS} -o ${EXEC} ${OBJS}

debug: ${EXEC}
debug: CC += ${CFDEBUG}

clean:
	rm -rf ./*.o
	rm -rf ./ldm

mrproper: clean
	rm ${EXEC}

install-main: ldm
	test -d ${DESTDIR}${BINDIR} || mkdir -p ${DESTDIR}${BINDIR}
	install -m755 ldm ${DESTDIR}${BINDIR}/ldm

install-systemd: ldm.service
	test -d ${DESTDIR}${SYSTEMDDIR} || mkdir -p ${DESTDIR}${SYSTEMDDIR}
	install -m644 ldm.service ${DESTDIR}${SYSTEMDDIR}/

install: all install-main install-systemd

.PHONY: all debug clean mrproper install install-main install-systemd
