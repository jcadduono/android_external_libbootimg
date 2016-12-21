LIBBOOTIMG_SRC := libbootimg.c mincrypt/sha.c

BOOTIMG_SRC := bootimg.c

CFLAGS += -Wall -Wpedantic -Wextra -std=gnu99 -Os -s

ifdef BOOTIMG_NO_MTK
	CFLAGS += -DNO_MTK_SUPPORT=1
endif

MINGW32 := x86_64-w64-mingw32

all: bootimg libbootimg.so bootimg.exe libbootimg.dll

bootimg: $(BOOTIMG_SRC) $(LIBBOOTIMG_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

libbootimg.so: $(LIBBOOTIMG_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fPIC $^ -o $@

bootimg.exe: $(BOOTIMG_SRC) $(LIBBOOTIMG_SRC)
	$(MINGW32)-gcc $(CFLAGS) $(LDFLAGS) $^ -o $@

libbootimg.dll: $(LIBBOOTIMG_SRC)
	$(MINGW32)-gcc $(CFLAGS) $(LDFLAGS) -shared -Wl,--out-implib,libbootimg_dll.a $^ -o $@

clean:
	$(RM) -v bootimg *.exe *.dll *.a *.o *.so

