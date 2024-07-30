PKOC_PROGRAMS=pkoc-init-pd pkoc-mfg pkoc-mfgrep pkoc-reader

CC=clang
CFLAGS=-c -g -I../include -Wall -Werror
LINK=clang
LDFLAGS=-g -ljansson

all:	${PKOC_PROGRAMS}

clean:
	rm -f *.o core ${PKOC_PROGRAMS}

pkoc-init-pd:	pkoc-init-pd.o Makefile
	${LINK} -o pkoc-init-pd pkoc-init-pd.o ${LDFLAGS}

pkoc-mfg:	pkoc-mfg.o pkoc-parse.o Makefile
	${LINK} -o pkoc-mfg pkoc-mfg.o pkoc-parse.o ${LDFLAGS}

pkoc-mfgrep:	pkoc-mfgrep.o pkoc-parse.o pkoc-osdp-interface.o Makefile
	${LINK} -o pkoc-mfgrep pkoc-mfgrep.o pkoc-parse.o pkoc-osdp-interface.o ${LDFLAGS}

pkoc-reader:	pkoc-reader.o Makefile
	${LINK} -o pkoc-reader pkoc-reader.o

pkoc-init-pd.o:	pkoc-init-pd.c
	${CC} ${CFLAGS} pkoc-init-pd.c 

pkoc-mfg.o:	pkoc-mfg.c
	${CC} ${CFLAGS} pkoc-mfg.c 

pkoc-mfgrep.o:	pkoc-mfgrep.c
	${CC} ${CFLAGS} pkoc-mfgrep.c 

pkoc-osdp-interface.o:	pkoc-osdp-interface.c
	${CC} ${CFLAGS} pkoc-osdp-interface.c

pkoc-parse.o:	pkoc-parse.c
	${CC} ${CFLAGS} pkoc-parse.c

pkoc-reader.o:	pkoc-reader.c
	${CC} ${CFLAGS} pkoc-reader.c

