OBJS   = multi_file.o util.o wiiudisc.o main.o
TARGET = wudex
CFLAGS = -ggdb -D_FILE_OFFSET_BITS=64 -std=gnu99
LDFLAGS = -lcrypto

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJS)

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: clean
