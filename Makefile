CC=clang
LD=clang
CFLAGS=-g -Os -Wall -pedantic
LDFLAGS=

TARGET=ecdsa_cert.out

SOURCES=$(wildcard *.c slac/*.c)
OBJECTS=$(SOURCES:.c=.o)

LIBS=\
	-L..\
	-lmbedtls\
  	-lmbedcrypto\
  	-lmbedx509\
	-lm\
	-lrt\

INCLUDES=-I..

all: $(TARGET)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all