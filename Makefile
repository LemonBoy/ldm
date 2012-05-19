CC	?= gcc
CFLAGS ?= -O2
LDFLAGS += -ludev
CFDEBUG = -g3 -pedantic -Wall -Wunused-parameter -Wlong-long\
		  -Wsign-conversion -Wconversion -Wimplicit-function-declaration

EXEC = ldm
SRCS = ldm.c
OBJS = ${SRCS:.c=.o}

PREFIX?=/usr/local
BINDIR=${PREFIX}/bin
DAEMONDIR=/etc/rc.d

all: ${EXEC}

.c.o:
	${CC} ${CFLAGS} -o $@ -c $<

${EXEC}: ${OBJS}
	${CC} ${LDFLAGS} -o ${EXEC} ${OBJS}

debug: ${EXEC}
debug: CC += ${CFDEBUG}

clean:
	rm -rf ./*.o

mrproper: clean
	rm ${EXEC}

install-main: ldm
	test -d ${DESTDIR}${BINDIR} || mkdir -p ${DESTDIR}${BINDIR}
	install -m755 ldm ${DESTDIR}${BINDIR}/ldm

install-daemon: ldm.daemon
	test -d ${DESTDIR}${DAEMONDIR} || mkdir -p ${DESTDIR}${DAEMONDIR}
	install -m755 ldm.daemon ${DESTDIR}${DAEMONDIR}/ldm

install: all install-main install-daemon

.PHONY: all debug clean mrproper install install-main install-daemon
