all: bootimg

BOOTIMG_OBJ := bootimg.o libbootimg.o mincrypt/sha.o

bootimg: $(BOOTIMG_OBJ)
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	$(RM) -f bootimg $(BOOTIMG_OBJ)

