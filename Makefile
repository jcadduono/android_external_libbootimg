all: bootimg

BOOTIMG_SRC := bootimg.c libbootimg.c mincrypt/sha.c
CFLAGS += -Wall -Wpedantic -Wextra -std=gnu99

bootimg: $(BOOTIMG_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	$(RM) -f bootimg $(BOOTIMG_SRC:.c=.o)

