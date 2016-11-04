all: bootimg bootimg.exe libbootimg.dll

LIBBOOTIMG_SRC := libbootimg.c mincrypt/sha.c

BOOTIMG_SRC := bootimg.c

CFLAGS += -Wall -Wpedantic -Wextra -std=gnu99 -Os -s

MINGW32 := x86_64-w64-mingw32

bootimg: $(BOOTIMG_SRC) $(LIBBOOTIMG_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

bootimg.exe: $(BOOTIMG_SRC) $(LIBBOOTIMG_SRC)
	$(MINGW32)-gcc $(CFLAGS) $(LDFLAGS) $^ -o $@

libbootimg.dll: $(LIBBOOTIMG_SRC)
	$(MINGW32)-gcc $(CFLAGS) $(LDFLAGS) -shared -Wl,--out-implib,libbootimg_dll.a $^ -o $@

clean:
	$(RM) -f bootimg *.exe *.dll *.a *.o

