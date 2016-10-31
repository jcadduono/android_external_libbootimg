/*
** Copyright 2016, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

#include "bootimg.h"

#define APP_NAME "bootimg"

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO,  APP_NAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { __android_log_print(ANDROID_LOG_ERROR, APP_NAME, __VA_ARGS__); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#else
#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#endif

// create new files as 0644
#define NEW_FILE_PERMISSIONS (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

// create new directories as 0755
#define NEW_DIR_PERMISSIONS (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

enum {
	MODE_NONE,
	MODE_UNPACK,
	MODE_CREATE
};

static int write_string_to_file(const char* file, const char* string)
{
	int fd, len = strlen(string);

	fd = open(file, O_CREAT | O_TRUNC | O_WRONLY, NEW_FILE_PERMISSIONS);
	if (fd < 0)
		return EACCES;

	if (len && write(fd, string, len) != len)
		return EIO;

	if (write(fd, "\n", 1) != 1)
		return EIO;

	close(fd);
	return 0;
}

static int write_binary_to_file(const char* file, const byte* binary, const ssize_t size)
{
	int fd = open(file, O_CREAT | O_TRUNC | O_WRONLY, NEW_FILE_PERMISSIONS);
	if (fd < 0)
		return EACCES;

	if (size && write(fd, binary, size) != size)
		return EIO;

	close(fd);
	return 0;
}

static char *basename(char const *path)
{
	const char *s = strrchr(path, '/');
	if (!s) {
		return strdup(path);
	} else {
		return strdup(s + 1);
	}
}

int main(const int argc, const char** argv)
{
	boot_img image;
	char tmp[PATH_MAX], *bname;
	char hextmp[16];
	const char *input = 0, *output = 0;
	const char *kernel = 0, *ramdisk = 0, *second = 0;
	const char *dt = 0, *board = 0, *cmdline = 0;
	int pagesize = 0;
	uint32_t base = 0;
	uint32_t kernel_offset = 0, ramdisk_offset = 0;
	uint32_t second_offset = 0, tags_offset = 0;
	int mode = MODE_NONE;
	int i, ret;

	if (argc < 1)
		goto usage;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "x")
		 || !strcmp(argv[i], "-x")
		 || !strcmp(argv[i], "--unpack")) {
			mode = MODE_UNPACK;
		} else
		if (!strcmp(argv[i], "c")
		 || !strcmp(argv[i], "-c")
		 || !strcmp(argv[i], "--create")) {
			mode = MODE_CREATE;
		}
	}

	if (mode == MODE_NONE)
		goto usage;

	if (mode == MODE_UNPACK)
		goto unpack;

	for (i = 1; i < argc; i++) {
		if (i == argc - 1) {
			if (!output) {
				output = argv[i];
			} else
				goto usage;
			break;
		}
		if (!strcmp(argv[i], "x")
		 || !strcmp(argv[i], "-x")
		 || !strcmp(argv[i], "--unpack")) {
			// do nothing
		} else
		if (!strcmp(argv[i], "c")
		 || !strcmp(argv[i], "-c")
		 || !strcmp(argv[i], "--create")) {
			// do nothing
		} else
		if (!strcmp(argv[i], "-o")
		 || !strcmp(argv[i], "--output")) {
			output = argv[++i];
		} else
		if (!strcmp(argv[i], "-k")
		 || !strcmp(argv[i], "--kernel")) {
			kernel = argv[++i];
		} else
		if (!strcmp(argv[i], "-r")
		 || !strcmp(argv[i], "--ramdisk")) {
			ramdisk = argv[++i];
		} else
		if (!strcmp(argv[i], "-s")
		 || !strcmp(argv[i], "--second")) {
			second = argv[++i];
		} else
		if (!strcmp(argv[i], "-d")
		 || !strcmp(argv[i], "--dt")) {
			dt = argv[++i];
		} else
		if (!strcmp(argv[i], "-m")
		 || !strcmp(argv[i], "--board")) {
			board = argv[++i];
		} else
		if (!strcmp(argv[i], "-l")
		 || !strcmp(argv[i], "--cmdline")) {
			cmdline = argv[++i];
		} else
		if (!strcmp(argv[i], "-p")
		 || !strcmp(argv[i], "--pagesize")) {
			pagesize = strtoul(argv[++i], 0, 10);
		} else
		if (!strcmp(argv[i], "-b")
		 || !strcmp(argv[i], "--base")) {
			base = strtoul(argv[++i], 0, 16);
		} else
		if (!strcmp(argv[i], "-ko")
		 || !strcmp(argv[i], "--kernel_offset")) {
			kernel_offset = strtoul(argv[++i], 0, 16);
		} else
		if (!strcmp(argv[i], "-ro")
		 || !strcmp(argv[i], "--ramdisk_offset")) {
			ramdisk_offset = strtoul(argv[++i], 0, 16);
		} else
		if (!strcmp(argv[i], "-so")
		 || !strcmp(argv[i], "--second_offset")) {
			second_offset = strtoul(argv[++i], 0, 16);
		} else
		if (!strcmp(argv[i], "-to")
		 || !strcmp(argv[i], "--tags_offset")) {
			tags_offset = strtoul(argv[++i], 0, 16);
		} else
		if (!output) {
			output = argv[i];
		} else
			goto usage;
	}

	if (!output)
		goto usage;

	ret = create_boot_image(&image,
		kernel, ramdisk, second, dt,
		board, cmdline, pagesize, base,
		kernel_offset, ramdisk_offset,
		second_offset, tags_offset);
	if (ret) {
		LOGE("Failed to initialize boot image: %s", strerror(ret));
		return ret;
	}

	ret = write_boot_image(&image, output);
	if (ret) {
		LOGE("Failed to write boot image '%s': %s",
			output, strerror(ret));
		return ret;
	}

	free_boot_image(&image);

	return ret;

unpack:
	for (i = 1; i < argc; i++) {
		if (i == argc - 1) {
			if (!input) {
				input = argv[i];
			} else
			if (!output) {
				output = argv[i];
			} else
				goto usage;
			break;
		}
		if (!strcmp(argv[i], "x")
		 || !strcmp(argv[i], "-x")
		 || !strcmp(argv[i], "--unpack")) {
			// do nothing
		} else
		if (!strcmp(argv[i], "c")
		 || !strcmp(argv[i], "-c")
		 || !strcmp(argv[i], "--create")) {
			// do nothing
		} else
		if (!strcmp(argv[i], "-i")
		 || !strcmp(argv[i], "--input")) {
			input = argv[++i];
		} else
		if (!strcmp(argv[i], "-o")
		 || !strcmp(argv[i], "--output")) {
			output = argv[++i];
		} else
		if (!input) {
			input = argv[i];
		} else
		if (!output) {
			output = argv[i];
		} else
			goto usage;
	}

	if (!input || !output)
		goto usage;

	ret = load_boot_image(&image, input);
	if (ret) {
		LOGE("Failed to load boot image '%s': %s",
			input, strerror(ret));
		return ret;
	}

	if (mkdir(output, NEW_DIR_PERMISSIONS)) {
		LOGE("Could not create output directory '%s': %s",
			output, strerror(errno));
		return errno;
	}

	bname = basename(input);

	LOGV("BOARD_MAGIC \"%s\"", image.hdr.board);
	sprintf(tmp, "%s/%s-board", output, bname);
	write_string_to_file(tmp, (char*)image.hdr.board);

	LOGV("BOARD_KERNEL_CMDLINE \"%s\"", image.hdr.cmdline);
	sprintf(tmp, "%s/%s-cmdline", output, bname);
	write_string_to_file(tmp, (char*)image.hdr.cmdline);

	base = image.hdr.kernel_addr - 0x00008000;
	LOGV("BOARD_KERNEL_BASE 0x%08X", base);
	sprintf(tmp, "%s/%s-base", output, bname);
	sprintf(hextmp, "%08x", base);
	write_string_to_file(tmp, hextmp);

	LOGV("BOARD_PAGE_SIZE %d", image.hdr.pagesize);
	sprintf(tmp, "%s/%s-pagesize", output, bname);
	sprintf(hextmp, "%d", image.hdr.pagesize);
	write_string_to_file(tmp, hextmp);

	kernel_offset = image.hdr.kernel_addr - base;
	LOGV("BOARD_KERNEL_OFFSET 0x%08X", kernel_offset);
	sprintf(tmp, "%s/%s-kernel_offset", output, bname);
	sprintf(hextmp, "%08x", kernel_offset);
	write_string_to_file(tmp, hextmp);

	ramdisk_offset = image.hdr.ramdisk_addr - base;
	LOGV("BOARD_RAMDISK_OFFSET 0x%08X", ramdisk_offset);
	sprintf(tmp, "%s/%s-ramdisk_offset", output, bname);
	sprintf(hextmp, "%08x", ramdisk_offset);
	write_string_to_file(tmp, hextmp);

	second_offset = image.hdr.second_addr - base;
	LOGV("BOARD_SECOND_OFFSET 0x%08X", second_offset);
	sprintf(tmp, "%s/%s-second_offset", output, bname);
	sprintf(hextmp, "%08x", second_offset);
	write_string_to_file(tmp, hextmp);

	tags_offset = image.hdr.tags_addr - base;
	LOGV("BOARD_TAGS_OFFSET 0x%08X", tags_offset);
	sprintf(tmp, "%s/%s-tags_offset", output, bname);
	sprintf(hextmp, "%08x", tags_offset);
	write_string_to_file(tmp, hextmp);

	LOGV("BOARD_KERNEL_SIZE %d", image.hdr.kernel_size);
	sprintf(tmp, "%s/%s-kernel", output, bname);
	write_binary_to_file(tmp, image.kernel, image.hdr.kernel_size);

	LOGV("BOARD_RAMDISK_SIZE %d", image.hdr.ramdisk_size);
	sprintf(tmp, "%s/%s-ramdisk", output, bname);
	write_binary_to_file(tmp, image.ramdisk, image.hdr.ramdisk_size);

	LOGV("BOARD_SECOND_SIZE %d", image.hdr.second_size);
	sprintf(tmp, "%s/%s-second", output, bname);
	write_binary_to_file(tmp, image.second, image.hdr.second_size);

	LOGV("BOARD_DT_SIZE %d", image.hdr.dt_size);
	sprintf(tmp, "%s/%s-dt", output, bname);
	write_binary_to_file(tmp, image.dt, image.hdr.dt_size);

	free(bname);
	free_boot_image(&image);

	return 0;
usage:
	LOGE("Usage: %s [args...]", argv[0]);
	LOGE(
		"  -x, --unpack   - unpacks an Android boot image\n"
		"     -i,  --input \"boot.img\"\n"
		"     -o,  --output \"output directory\"\n"
		"  -c, --create   - creates an Android boot image\n"
		"     -o,  --output \"boot.img\"\n"
		"   [ -k,  --kernel \"kernel\"        ]\n"
		"   [ -r,  --ramdisk \"ramdisk\"      ]\n"
		"   [ -s,  --second \"second\"        ]\n"
		"   [ -d,  --dt \"dt.img\"            ]\n"
		"   [ -m,  --board \"board magic\"    ]\n"
		"   [ -l,  --cmdline \"boot cmdline\" ]\n"
		"   [ -p,  --pagesize <size>        ]\n"
		"   [ -b,  --base <hex>             ]\n"
		"   [ -ko, --kernel_offset <hex>    ]\n"
		"   [ -ro, --ramdisk_offset <hex>   ]\n"
		"   [ -so, --second_offset <hex>    ]\n"
		"   [ -to, --tags_offset <hex>      ]"
	);
	return EINVAL;
}
