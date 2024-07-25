EXEC = hgota libnetat hgicf hgpriv

CFLAGS += -D__linux__
LDFLAGS += -lm

all: $(EXEC)
	$(shell rm -rf bin;	mkdir bin)
	for i in $(EXEC) ; do mv -fv $$i bin/$$i ; done
	
tcp_test: tcp_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $@.c $(LDLIBS)

dsleep_test: dsleep_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $@.c $(LDLIBS)

hgota: libota.o hgota.o fwinfo.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ libota.o hgota.o fwinfo.o $(LDLIBS)

hguevent: hguevent.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $@.c $(LDLIBS)

libnetat: libnetat.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $@.c $(LDLIBS)

hgics: hgics.o blenc.o hgics_blenc.o hgics_relay.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ hgics.o hgics_blenc.o hgics_relay.o blenc.o $(LDLIBS)

hgicf: hgicf.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $@.c $(LDLIBS)

hgpriv: hgpriv.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $@.c $(LDLIBS)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

