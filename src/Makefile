PKOC_PROGRAMS=pkoc-init-pd pkoc-mfg pkoc-mfgrep pkoc-reader

CC=clang
CFLAGS=-c -g -I../include -I/opt/openbadger/include -I/usr/include/PCSC -Wall -Werror
LINK=clang
LDFLAGS=-g -ljansson -lpcsclite /opt/openbadger/lib/libeac-crypto_cyclone.a /opt/crypto/lib/libcyclone.a /opt/openbadger/lib/libopenbadger.a
LDFLAGS=-g \
  -L/opt/openbadger/lib -leac-crypto_cyclone -leac-encode -lopenbadger -L /opt/crypto/lib -lcyclone \
  -ljansson -lpcsclite

all:	${PKOC_PROGRAMS}
	mkdir -p ../opt/osdp-conformance/bin
	cp ${PKOC_PROGRAMS} ../opt/osdp-conformance/bin

clean:
	rm -f *.o core ${PKOC_PROGRAMS}

pkoc-init-pd:	pkoc-init-pd.o Makefile
	${LINK} -o pkoc-init-pd pkoc-init-pd.o ${LDFLAGS}

pkoc-mfg:	pkoc-mfg.o pkoc-parse.o Makefile
	${LINK} -o pkoc-mfg pkoc-mfg.o pkoc-parse.o ${LDFLAGS}

pkoc-mfgrep:	pkoc-mfgrep.o pkoc-parse.o pkoc-osdp-interface.o Makefile
	${LINK} -o pkoc-mfgrep pkoc-mfgrep.o pkoc-parse.o pkoc-osdp-interface.o ${LDFLAGS}

pkoc-reader:	pkoc-reader.o pkoc-nfc.o pkoc-osdp-interface.o pkoc-parse.o Makefile
	${LINK} -o pkoc-reader pkoc-reader.o \
	  pkoc-nfc.o pkoc-osdp-interface.o pkoc-parse.o ${LDFLAGS}

pkoc-init-pd.o:	pkoc-init-pd.c
	${CC} ${CFLAGS} pkoc-init-pd.c 

pkoc-mfg.o:	pkoc-mfg.c
	${CC} ${CFLAGS} pkoc-mfg.c 

pkoc-mfgrep.o:	pkoc-mfgrep.c
	${CC} ${CFLAGS} pkoc-mfgrep.c 

pkoc-nfc.o:	pkoc-nfc.c
	${CC} ${CFLAGS} -DALLOCATE_SELECT pkoc-nfc.c

pkoc-osdp-interface.o:	pkoc-osdp-interface.c
	${CC} ${CFLAGS} pkoc-osdp-interface.c

pkoc-parse.o:	pkoc-parse.c
	${CC} ${CFLAGS} pkoc-parse.c

pkoc-reader.o:	pkoc-reader.c
	${CC} ${CFLAGS} pkoc-reader.c

