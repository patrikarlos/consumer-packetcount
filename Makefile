CFLAGS+=-Os -g -Wall $(shell pkg-config libcap_utils-0.7 --cflags)
LDFLAGS+=
LIBS=$(shell pkg-config libcap_utils-0.7 --libs)
OBJS=main.o
TARGET=packetcount
PREFIX=/usr/local
DESTDIR=

.PHONY: clean install

all: $(TARGET)

$(TARGET): $(OBJS)	
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $(TARGET)

clean:
	rm -f *.o $(TARGET)

install:
	install -d $(DESTDIR)$(PREFIX)/bin
	install $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/$(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
