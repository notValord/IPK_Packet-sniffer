TARGET=ipk-sniffer
SOURCES=packet_sniffer.c

CC=gcc
FLAGS=-lpcap

OBJECTS=$(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $< $(FLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(FLAGS)

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean