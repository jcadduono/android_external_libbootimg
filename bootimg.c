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
#include <dirent.h>
#include <sys/stat.h>

#include "bootimg.h"
#include "mincrypt/sha.h"

#define APP_NAME "bootimg"

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO,  APP_NAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { __android_log_print(ANDROID_LOG_ERROR, APP_NAME, __VA_ARGS__); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#else
#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#endif

/* create new files as 0640 */
#define NEW_FILE_PERMISSIONS (S_IRUSR | S_IWUSR | S_IRGRP)

/* create new directories as 0750 */
#define NEW_DIR_PERMISSIONS (S_IRWXU | S_IRGRP | S_IXGRP)

/* string value used to ignore/delete items when creating/updating a boot image */
#define DELETE_VALUE "!"

/* mingw32-gcc compatibility */
#if defined(_WIN32) || defined(__WIN32__)
#define mkdir(A, B) mkdir(A)
#else
#define O_BINARY 0
#endif

/* modes of operation */
enum {
	MODE_NONE,
	MODE_UNPACK,
	MODE_CREATE,
	MODE_UPDATE,
	MODE_INFO
};

/* args set by user in command */
enum
{
	ARG_BOARD           = 1U <<  0,
	ARG_CMDLINE         = 1U <<  1,
	ARG_MTK_HEADER      = 1U <<  2,
	ARG_PAGESIZE        = 1U <<  3,
	ARG_BASE            = 1U <<  4,
	ARG_KERNEL_OFFSET   = 1U <<  5,
	ARG_RAMDISK_OFFSET  = 1U <<  6,
	ARG_SECOND_OFFSET   = 1U <<  7,
	ARG_TAGS_OFFSET     = 1U <<  8,
#ifndef NO_MTK_SUPPORT
	ARG_KERNEL_MTK      = 1U <<  9,
	ARG_RAMDISK_MTK     = 1U << 10,
	ARG_SECOND_MTK      = 1U << 11,
	ARG_DT_MTK          = 1U << 12,
#endif
	ARG_KERNEL          = 1U << 13,
	ARG_RAMDISK         = 1U << 14,
	ARG_SECOND          = 1U << 15,
	ARG_DT              = 1U << 16,
	ARG_CHROMEOS        = 1U << 17, /* unused */
	ARG_CMDLINE_ARG     = 1U << 18,
	ARG_HASH            = 1U << 19,
	ARG_ACTUALHASH      = 1U << 20, /* unused */
	ARG_OS_VERSION      = 1U << 21,
	ARG_PATCH_LEVEL     = 1U << 22,
};

/* match arg flags (for verbose output) */
enum
{
	INFO_MAGIC          = 1U <<  0,
	INFO_CMDLINE        = 1U <<  1,
	INFO_MTK_HEADER     = 1U <<  2,
	INFO_PAGESIZE       = 1U <<  3,
	INFO_BASE           = 1U <<  4,
	INFO_KERNEL_OFFSET  = 1U <<  5,
	INFO_RAMDISK_OFFSET = 1U <<  6,
	INFO_SECOND_OFFSET  = 1U <<  7,
	INFO_TAGS_OFFSET    = 1U <<  8,
#ifndef NO_MTK_SUPPORT
	INFO_KERNEL_MTK     = 1U <<  9,
	INFO_RAMDISK_MTK    = 1U << 10,
	INFO_SECOND_MTK     = 1U << 11,
	INFO_DT_MTK         = 1U << 12,
#endif
	INFO_KERNEL_SIZE    = 1U << 13,
	INFO_RAMDISK_SIZE   = 1U << 14,
	INFO_SECOND_SIZE    = 1U << 15,
	INFO_DT_SIZE        = 1U << 16,
	INFO_CHROMEOS       = 1U << 17,
	INFO_CMDLINE_ARG    = 1U << 18, /* unused */
	INFO_HASH           = 1U << 19,
	INFO_ACTUALHASH     = 1U << 20,
	INFO_OS_VERSION     = 1U << 21,
	INFO_PATCH_LEVEL    = 1U << 22,
};

static int write_string_to_file(const char *file, const char *string)
{
	int fd, len = 0;

	if (string)
		len = strlen(string);

	fd = open(file, O_CREAT | O_TRUNC | O_WRONLY, NEW_FILE_PERMISSIONS);
	if (fd < 0)
		return errno;

	if (len && write(fd, string, len) != len)
		goto oops;

	if (write(fd, "\n", 1) != 1)
		goto oops;

	close(fd);
	return 0;
oops:
	close(fd);
	unlink(file);
	return EIO;
}

static int read_string_from_file(const char* file, char *buf, off_t len)
{
	int fd;
	char *c;
	off_t rlen;

	if ((fd = open(file, O_RDONLY)) < 0)
		return errno;

	rlen = read(fd, buf, len - 1);
	if (rlen < 0) {
		close(fd);
		return EIO;
	}

	*(buf + rlen + 1) = 0;

	if ((c = strchr(buf, '\r')) || (c = strchr(buf, '\n')))
		*c = 0; /* stop at newline */

	close(fd);
	return 0;
}

static char *read_hash(const byte *hash)
{
	char *str = malloc(SHA_DIGEST_SIZE * 2 + 1);
	char *c = str;
	const byte *h = hash;
	for (; c < str + SHA_DIGEST_SIZE * 2; h++) {
		c += sprintf(c, "%02x", *h);
	}
	*c = 0;
	return str;
}

void print_boot_info(const boot_img *image, const unsigned info)
{
	if (info & INFO_MAGIC)
		LOGV("BOARD_MAGIC \"%s\"", image->hdr.board);
	if (info & INFO_CMDLINE)
		LOGV("BOARD_CMDLINE \"%s\"", image->hdr.cmdline);

	if (info & INFO_OS_VERSION && image->hdr.os_version) {
		char *os_version = bootimg_get_os_version(image);
		if (os_version) {
			LOGV("BOARD_OS_VERSION %s", os_version);
			free(os_version);
		}
	}
	if (info & INFO_PATCH_LEVEL && image->hdr.os_version) {
		char *patch_level = bootimg_get_patch_level(image);
		if (patch_level) {
			LOGV("BOARD_OS_PATCH_LEVEL %s", patch_level);
			free(patch_level);
		}
	}

	if (info & INFO_PAGESIZE)
		LOGV("BOARD_PAGESIZE %u", image->hdr.pagesize);

	if (info & INFO_BASE)
		LOGV("BOARD_BASE 0x%08X", image->base);
	if (info & INFO_KERNEL_OFFSET)
		LOGV("BOARD_KERNEL_OFFSET 0x%08X", image->kernel.offset);
	if (info & INFO_RAMDISK_OFFSET)
		LOGV("BOARD_RAMDISK_OFFSET 0x%08X", image->ramdisk.offset);
	if (info & INFO_SECOND_OFFSET)
		LOGV("BOARD_SECOND_OFFSET 0x%08X", image->second.offset);
	if (info & INFO_TAGS_OFFSET)
		LOGV("BOARD_TAGS_OFFSET 0x%08X", image->tags_offset);

	if (info & INFO_KERNEL_SIZE)
		LOGV("BOARD_KERNEL_SIZE %u", (unsigned)image->kernel.size);
	if (info & INFO_RAMDISK_SIZE)
		LOGV("BOARD_RAMDISK_SIZE %u", (unsigned)image->ramdisk.size);
	if (info & INFO_SECOND_SIZE)
		LOGV("BOARD_SECOND_SIZE %u", (unsigned)image->second.size);
	if (info & INFO_DT_SIZE)
		LOGV("BOARD_DT_SIZE %u", (unsigned)image->dt.size);

#ifndef NO_MTK_SUPPORT
	if (info & INFO_KERNEL_MTK && image->kernel.mtk_header)
		LOGV("BOARD_KERNEL_MTK \"%s\"", image->kernel.mtk_header->string);
	if (info & INFO_RAMDISK_MTK && image->ramdisk.mtk_header)
		LOGV("BOARD_RAMDISK_MTK \"%s\"", image->ramdisk.mtk_header->string);
	if (info & INFO_SECOND_MTK && image->second.mtk_header)
		LOGV("BOARD_SECOND_MTK \"%s\"", image->second.mtk_header->string);
	if (info & INFO_DT_MTK && image->dt.mtk_header)
		LOGV("BOARD_DT_MTK \"%s\"", image->dt.mtk_header->string);
#endif

	if (info & INFO_CHROMEOS && image->chromeos)
		LOGV("BOARD_CHROMEOS %u", image->chromeos);

	if (info & INFO_HASH) {
		char *hash = read_hash((byte*)image->hdr.hash);
		if (hash) {
			LOGV("BOARD_HASH 0x%s", hash);
			free(hash);
		}
	}
	if (info & INFO_ACTUALHASH) {
		byte *bytes = bootimg_generate_hash(image);
		if (bytes) {
			char *hash = read_hash(bytes);
			if (hash) {
				LOGV("ACTUALHASH 0x%s", hash);
				free(hash);
			}
			free(bytes);
		}
	}
}

static void print_usage(const char *app)
{
	LOGE("Usage: %s [xcuvvf] [args...]\n", app);
	LOGE(
		" Modes:\n"
		"  -x, --unpack        - unpack an Android boot image\n"
		"  -c, --create        - create an Android boot image\n"
		"  -u, --update        - update an Android boot image\n"
		"  -v, -vv, --verbose  - print boot image details\n"
		"  -H, --help          - print usage information\n"
	);
	LOGE(
		" Options: (set value only for create/update mode)\n"
		"   [ -k,  --kernel \"kernel\"          ]\n"
		"   [ -r,  --ramdisk \"ramdisk\"        ]\n"
		"   [ -s,  --second \"second\"          ]\n"
		"   [ -d,  --dt \"dt.img\"              ]\n"
		"   [ -m,  --board \"board magic\"      ]\n"
		"   [ -os, --os_version \"A.B.C\"       ]\n"
		"   [ -pl, --patch_level \"YYYY-MM-DD\" ]\n"
		"   [ -l,  --cmdline \"boot cmdline\"   ]\n"
		"   [ -a,  --arg \"cmdline\" \"value\"    ]\n"
		"   [ -p,  --pagesize <size>          ]\n"
		"   [ -b,  --base <hex>               ]\n"
		"   [ -ko, --kernel_offset <hex>      ]\n"
		"   [ -ro, --ramdisk_offset <hex>     ]\n"
		"   [ -so, --second_offset <hex>      ]\n"
		"   [ -to, --tags_offset <hex>        ]\n"
		"   [ -h,  --hash                     ]\n"
	);
#ifndef NO_MTK_SUPPORT
	LOGE(
		" Options for MediaTek devices:\n"
		"   [ -km, --kernel_mtk \"KERNEL\"      ]\n"
		"   [ -rm, --ramdisk_mtk \"ROOTFS\"     ]\n"
		"   [ -sm, --second_mtk \"SECOND\"      ]\n"
		"   [ -tm, --dt_mtk \"DTIMAGE\"         ]\n"
	);
#endif
	LOGE(
		" Unpack:\n"
		"     -i,  --input \"boot.img\"\n"
		"     -o,  --output \"directory\"\n"
		" Create:\n"
		"     -o,  --output \"boot.img\"\n"
		"     -i,  --input \"directory\"\n"
		" Update:\n"
		"     -i,  --input \"boot.img\"\n"
		"   [ -o,  --output \"boot.img\"        ]\n"
	);
	LOGE(
		"To remove an item from the image, specify "
		DELETE_VALUE " as its value.\n"
	);
}

/* returned by any invalid command */
#define usage(...) { \
	print_usage(argv[0]); \
	LOGE(__VA_ARGS__); \
	ret = EINVAL; \
	goto free; \
}

/* shortcuts to reduce code */
#define unset(item) { if (item) { free(item); item = 0; } }
#define specify(item) usage("You need to specify %s!", item)
#define failto(item) { LOGE("Failed to %s: %s", item, strerror(ret)); goto free; }
#define requireval { if (i > argc - 2) usage("%s requires a value in this mode!", argv[i]); }
#define breakifdelete { if (!strcmp(argv[i + 1], DELETE_VALUE)) { i++; break; } }
#define foundfile(item) { if (verbose > 1) LOGV("Found %s: %s", item, file); }
#define setfile(name) sprintf(file, "%s/%s", output, name);

int main(const int argc, const char** argv)
{
	boot_img *image = 0;
	struct stat st = {.st_dev = 0};
	struct dirent *dp;
	DIR *dfd;
	const char *c, *input = 0, *output = 0;
	char file[PATH_MAX], buf[1024], hex[16],
		*board = 0, *os_version = 0, *patch_level = 0, *cmdline = 0,
		*kernel = 0, *ramdisk = 0, *second = 0, *dt = 0;
#ifndef NO_MTK_SUPPORT
	char *kernel_mtk = 0, *ramdisk_mtk = 0, *second_mtk = 0, *dt_mtk = 0;
#endif
	uint32_t base = 0, tags_offset = 0,
		kernel_offset = 0, ramdisk_offset = 0, second_offset = 0;
	int i, argstart, mode = MODE_NONE,
		pagesize = 0, ret = 0, verbose = 0;
	unsigned args = 0, info = 0;

	if (argc < 2)
		usage("Not enough arguments!");

	/* tar style argument parsing (only valid in first arg) */
	for (argstart = 2, c = argv[1]; *c; c++) {
		switch (*c) {
		case '-':
		case 'f':
			continue;
		case 'x':
			mode = MODE_UNPACK;
			continue;
		case 'c':
			mode = MODE_CREATE;
			continue;
		case 'u':
			mode = MODE_UPDATE;
			continue;
		case 'v':
			verbose++;
			continue;
		}
		mode = MODE_NONE;
		verbose = 0;
		argstart = 1;
		break;
	}

	/* handle mode changes so next section can parse args in the right mode */
	for (i = argstart; i < argc; i++) {
		if (!strcmp(argv[i], "-x") || !strcmp(argv[i], "--unpack"))
			mode = MODE_UNPACK;
		else
		if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--create"))
			mode = MODE_CREATE;
		else
		if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--update"))
			mode = MODE_UPDATE;
		else
		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
			verbose++;
		else
		if (!strcmp(argv[i], "-vv"))
			verbose += 2;
		else
		if (!strcmp(argv[i], "-H") || !strcmp(argv[i], "--help")) {
			print_usage(argv[0]);
			return 0;
		}
	}

	if (mode == MODE_NONE && verbose)
		mode = MODE_INFO;

	if (mode == MODE_NONE)
		specify("a mode of operation");

	for (i = argstart; i < argc; i++) {
		if (!strcmp(argv[i], "-x") || !strcmp(argv[i], "--unpack")
		 || !strcmp(argv[i], "-c") || !strcmp(argv[i], "--create")
		 || !strcmp(argv[i], "-u") || !strcmp(argv[i], "--update")
		 || !strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
			/* do nothing, we already handled these args */
		} else
		if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--input")) {
			requireval;
			input = argv[++i];
		} else
		if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
			if (mode == MODE_INFO)
				usage("You can't use %s in info mode!", argv[i]);
			requireval;
			output = argv[++i];
		} else
		if (!strcmp(argv[i], "-k") || !strcmp(argv[i], "--kernel")) {
			args |= ARG_KERNEL;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(kernel);
				requireval;
				breakifdelete;
				kernel = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--ramdisk")) {
			args |= ARG_RAMDISK;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(ramdisk);
				requireval;
				breakifdelete;
				ramdisk = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--second")) {
			args |= ARG_SECOND;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(second);
				requireval;
				breakifdelete;
				second = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--dt")) {
			args |= ARG_DT;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(dt);
				requireval;
				breakifdelete;
				dt = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--magic")
		 || !strcmp(argv[i], "--board")) {
			args |= ARG_BOARD;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(board);
				requireval;
				breakifdelete;
				board = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-os") || !strcmp(argv[i], "--os_version")) {
			args |= ARG_OS_VERSION;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(os_version);
				requireval;
				breakifdelete;
				os_version = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-pl") || !strcmp(argv[i], "--patch_level")) {
			args |= ARG_PATCH_LEVEL;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(patch_level);
				requireval;
				breakifdelete;
				patch_level = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--cmdline")) {
			args |= ARG_CMDLINE;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(cmdline);
				requireval;
				breakifdelete;
				cmdline = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--pagesize")) {
			args |= ARG_PAGESIZE;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				requireval;
				pagesize = strtoul(argv[++i], 0, 10);
			}
		} else
		if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--base")) {
			args |= ARG_BASE;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				requireval;
				base = strtoul(argv[++i], 0, 16);
			}
		} else
		if (!strcmp(argv[i], "-ko")
		 || !strcmp(argv[i], "--kernel_offset")) {
			args |= ARG_KERNEL_OFFSET;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				requireval;
				kernel_offset = strtoul(argv[++i], 0, 16);
			}
		} else
		if (!strcmp(argv[i], "-ro")
		 || !strcmp(argv[i], "--ramdisk_offset")) {
			args |= ARG_RAMDISK_OFFSET;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				requireval;
				ramdisk_offset = strtoul(argv[++i], 0, 16);
			}
		} else
		if (!strcmp(argv[i], "-so")
		 || !strcmp(argv[i], "--second_offset")) {
			args |= ARG_SECOND_OFFSET;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				requireval;
				second_offset = strtoul(argv[++i], 0, 16);
			}
		} else
		if (!strcmp(argv[i], "-to")
		 || !strcmp(argv[i], "--tags_offset")) {
			args |= ARG_TAGS_OFFSET;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				requireval;
				tags_offset = strtoul(argv[++i], 0, 16);
			}
		} else
#ifndef NO_MTK_SUPPORT
		if (!strcmp(argv[i], "-km") || !strcmp(argv[i], "-mk")
		 || !strcmp(argv[i], "--kernel_mtk")) {
			args |= ARG_KERNEL_MTK;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(kernel_mtk);
				requireval;
				breakifdelete;
				kernel_mtk = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-rm") || !strcmp(argv[i], "-mr")
		 || !strcmp(argv[i], "--ramdisk_mtk")) {
			args |= ARG_RAMDISK_MTK;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(ramdisk_mtk);
				requireval;
				breakifdelete;
				ramdisk_mtk = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-sm") || !strcmp(argv[i], "-ms")
		 || !strcmp(argv[i], "--second_mtk")) {
			args |= ARG_SECOND_MTK;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(second_mtk);
				requireval;
				breakifdelete;
				second_mtk = strdup(argv[++i]);
			}
		} else
		if (!strcmp(argv[i], "-dm") || !strcmp(argv[i], "-md")
		 || !strcmp(argv[i], "--dt_mtk")) {
			args |= ARG_DT_MTK;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				unset(dt_mtk);
				requireval;
				breakifdelete;
				dt_mtk = strdup(argv[++i]);
			}
		} else
#endif
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--hash")) {
			args |= ARG_HASH;
		} else
		if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--arg")) {
			args |= ARG_CMDLINE_ARG;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				if (i > argc - 3)
					usage("%s requires both an argument and a value!", argv[i]);
				i += 2; /* we should handle this in update section */
				continue;
			}
			usage("You can only use %s in update/create mode!", argv[i]);
		} else
		{ /* if it's not an argument, it's either an input or output */
			switch (mode) {
			case MODE_CREATE:
				if (!output) {
					output = argv[i];
					continue;
				}
				/* Fall-through */
			case MODE_INFO:
			case MODE_UPDATE:
			case MODE_UNPACK:
				if (!input) {
					input = argv[i];
					continue;
				}
				if (mode == MODE_INFO)
					break;
				if (!output) {
					output = argv[i];
					continue;
				}
			}
			usage("Unknown argument: %s", argv[i]);
		}
	}

	if (verbose > 1)
		info = -1 - INFO_ACTUALHASH; /* turn them all on! */
	else
		info = args;

	switch (mode) {
	case MODE_UNPACK:
	case MODE_INFO:
		goto info;
	case MODE_CREATE:
		goto create;
	case MODE_UPDATE:
		goto update;
	}

	goto free; /* this should never be reached, ret = 0 */

info:
	if (!input)
		specify("an input boot image");

	if (mode == MODE_UNPACK && !output)
		specify("an output directory");

	if (mode == MODE_UNPACK && !stat(output, &st)
	 && !S_ISDIR(st.st_mode) && (ret = ENOTDIR))
		failto("create output directory");

	if (!(image = load_boot_image(input)) && (ret = EINVAL))
		failto("load boot image");

	if (mode == MODE_UNPACK && !S_ISDIR(st.st_mode)
	 && mkdir(output, NEW_DIR_PERMISSIONS) && (ret = errno))
		failto("create output directory");

	if (!verbose)
		goto unpack;

	if (!info) {
		info = INFO_BASE | INFO_PAGESIZE | INFO_HASH
			| INFO_KERNEL_OFFSET | INFO_RAMDISK_OFFSET
			| INFO_SECOND_OFFSET | INFO_TAGS_OFFSET;

		if (*image->hdr.board)
			info |= INFO_MAGIC;
		if (image->hdr.os_version)
			info |= INFO_OS_VERSION | INFO_PATCH_LEVEL;
		if (*image->hdr.cmdline)
			info |= INFO_CMDLINE;
		if (image->kernel.size)
			info |= INFO_KERNEL_SIZE;
		if (image->ramdisk.size)
			info |= INFO_RAMDISK_SIZE;
		if (image->second.size)
			info |= INFO_SECOND_SIZE;
		if (image->dt.size)
			info |= INFO_DT_SIZE;
#ifndef NO_MTK_SUPPORT
		if (image->kernel.mtk_header)
			info |= INFO_KERNEL_MTK;
		if (image->ramdisk.mtk_header)
			info |= INFO_RAMDISK_MTK;
		if (image->second.mtk_header)
			info |= INFO_SECOND_MTK;
		if (image->dt.mtk_header)
			info |= INFO_DT_MTK;
#endif
		if (image->chromeos)
			info |= INFO_CHROMEOS;
	}

	if (args & ARG_HASH)
		info |= INFO_ACTUALHASH;

	print_boot_info(image, info);

	if (mode == MODE_INFO)
		goto free;
	/* otherwise continue to unpack */

unpack:
	args &= ~ARG_HASH; /* so --hash doesn't extract nothing */

	if (args & ARG_BOARD || !args) {
		setfile("board");
		write_string_to_file(file, (char*)image->hdr.board);
	}
	if (args & ARG_OS_VERSION || !args) {
		os_version = bootimg_get_os_version(image);
		if (os_version) {
			setfile("os_version");
			write_string_to_file(file, os_version);
		}
	}
	if (args & ARG_PATCH_LEVEL || !args) {
		patch_level = bootimg_get_patch_level(image);
		if (patch_level) {
			setfile("patch_level");
			write_string_to_file(file, patch_level);
		}
	}
	if (args & ARG_CMDLINE || !args) {
		setfile("cmdline");
		write_string_to_file(file, (char*)image->hdr.cmdline);
	}
	if (args & ARG_PAGESIZE || !args) {
		setfile("pagesize");
		sprintf(hex, "%u", image->hdr.pagesize);
		write_string_to_file(file, hex);
	}
	if (args & ARG_BASE || !args) {
		setfile("base");
		sprintf(hex, "%08X", image->base);
		write_string_to_file(file, hex);
	}
	if (args & ARG_KERNEL_OFFSET || !args) {
		setfile("kernel_offset");
		sprintf(hex, "%08X", image->kernel.offset);
		write_string_to_file(file, hex);
	}
	if (args & ARG_RAMDISK_OFFSET || !args) {
		setfile("ramdisk_offset");
		sprintf(hex, "%08X", image->ramdisk.offset);
		write_string_to_file(file, hex);
	}
	if (args & ARG_SECOND_OFFSET || !args) {
		setfile("second_offset");
		sprintf(hex, "%08X", image->second.offset);
		write_string_to_file(file, hex);
	}
	if (args & ARG_TAGS_OFFSET || !args) {
		setfile("tags_offset");
		sprintf(hex, "%08X", image->tags_offset);
		write_string_to_file(file, hex);
	}
	if (args & ARG_KERNEL || (!args && image->kernel.size)) {
		setfile("kernel");
		bootimg_save(image, BOOTIMG_KERNEL, file);
	}
	if (args & ARG_RAMDISK || (!args && image->ramdisk.size)) {
		setfile("ramdisk");
		bootimg_save(image, BOOTIMG_RAMDISK, file);
	}
	if (args & ARG_SECOND || (!args && image->second.size)) {
		setfile("second");
		bootimg_save(image, BOOTIMG_SECOND, file);
	}
	if (args & ARG_DT || (!args && image->dt.size)) {
		setfile("dt");
		bootimg_save(image, BOOTIMG_DT, file);
	}
#ifndef NO_MTK_SUPPORT
	if (args & ARG_KERNEL_MTK || (!args && image->kernel.mtk_header)) {
		setfile("kernel_mtk");
		if (image->kernel.mtk_header)
			write_string_to_file(file, (char*)image->kernel.mtk_header->string);
		else
			write_string_to_file(file, 0);
	}
	if (args & ARG_RAMDISK_MTK || (!args && image->ramdisk.mtk_header)) {
		setfile("ramdisk_mtk");
		if (image->ramdisk.mtk_header)
			write_string_to_file(file, (char*)image->ramdisk.mtk_header->string);
		else
			write_string_to_file(file, 0);
	}
	if (args & ARG_SECOND_MTK || (!args && image->second.mtk_header)) {
		setfile("second_mtk");
		if (image->second.mtk_header)
			write_string_to_file(file, (char*)image->second.mtk_header->string);
		else
			write_string_to_file(file, 0);
	}
	if (args & ARG_DT_MTK || (!args && image->dt.mtk_header)) {
		setfile("dt_mtk");
		if (image->dt.mtk_header)
			write_string_to_file(file, (char*)image->dt.mtk_header->string);
		else
			write_string_to_file(file, 0);
	}
#endif
	if (image->chromeos) {
		setfile("chromeos");
		write_string_to_file(file, 0);
	}

	goto free;

create:
	if (!output)
		specify("an output boot image");

	image = new_boot_image();

	if (!input)
		goto modify;

	if (!(dfd = opendir(input)) && (ret = errno))
		failto("open boot image directory");

	while ((dp = readdir(dfd))) {
		c = dp->d_name;
		if (strrchr(c, '-')) {
			/* prefixed by a base name, ex. boot.img */
			c = strrchr(c, '-') + 1;
			if (!*c)
				continue; /* - is the last character */
		}
		snprintf(file, sizeof(file), "%s/%s", input, dp->d_name);
		if (stat(file, &st) || !S_ISREG(st.st_mode))
			continue;

		if (!(args & ARG_BOARD) && !strcmp(c, "board")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("board");
			board = strdup(buf);
			args |= ARG_BOARD;
			continue;
		}
		if (!(args & ARG_OS_VERSION) && !strcmp(c, "os_version")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("os_version");
			os_version = strdup(buf);
			args |= ARG_OS_VERSION;
			continue;
		}
		if (!(args & ARG_PATCH_LEVEL) && !strcmp(c, "patch_level")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("patch_level");
			patch_level = strdup(buf);
			args |= ARG_PATCH_LEVEL;
			continue;
		}
		if (!(args & ARG_CMDLINE) && !strcmp(c, "cmdline")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("cmdline");
			cmdline = strdup(buf);
			args |= ARG_CMDLINE;
			continue;
		}
		if (!(args & ARG_PAGESIZE) && !strcmp(c, "pagesize")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("pagesize");
			pagesize = strtoul(buf, 0, 10);
			args |= ARG_PAGESIZE;
			continue;
		}
		if (!(args & ARG_BASE) && !strcmp(c, "base")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("base");
			base = strtoul(buf, 0, 16);
			args |= ARG_BASE;
			continue;
		}
		if (!(args & ARG_KERNEL_OFFSET) && !strcmp(c, "kernel_offset")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("kernel_offset");
			kernel_offset = strtoul(buf, 0, 16);
			args |= ARG_KERNEL_OFFSET;
			continue;
		}
		if (!(args & ARG_RAMDISK_OFFSET) && !strcmp(c, "ramdisk_offset")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("ramdisk_offset");
			ramdisk_offset = strtoul(buf, 0, 16);
			args |= ARG_RAMDISK_OFFSET;
			continue;
		}
		if (!(args & ARG_SECOND_OFFSET) && !strcmp(c, "second_offset")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("second_offset");
			second_offset = strtoul(buf, 0, 16);
			args |= ARG_SECOND_OFFSET;
			continue;
		}
		if (!(args & ARG_TAGS_OFFSET) && !strcmp(c, "tags_offset")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("tags_offset");
			tags_offset = strtoul(buf, 0, 16);
			args |= ARG_TAGS_OFFSET;
			continue;
		}
		if (!(args & ARG_KERNEL) && !strcmp(c, "kernel")) {
			foundfile("kernel");
			kernel = strdup(file);
			args |= ARG_KERNEL;
			continue;
		}
		if (!(args & ARG_RAMDISK) && !strcmp(c, "ramdisk")) {
			foundfile("ramdisk");
			ramdisk = strdup(file);
			args |= ARG_RAMDISK;
			continue;
		}
		if (!(args & ARG_SECOND) && !strcmp(c, "second")) {
			foundfile("second");
			second = strdup(file);
			args |= ARG_SECOND;
			continue;
		}
		if (!(args & ARG_DT) && !strcmp(c, "dt")) {
			foundfile("dt");
			dt = strdup(file);
			args |= ARG_DT;
			continue;
		}
#ifndef NO_MTK_SUPPORT
		if (!(args & ARG_KERNEL_MTK) && !strcmp(c, "kernel_mtk")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("kernel_mtk");
			kernel_mtk = strdup(buf);
			args |= ARG_KERNEL_MTK;
			continue;
		}
		if (!(args & ARG_RAMDISK_MTK) && !strcmp(c, "ramdisk_mtk")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("ramdisk_mtk");
			ramdisk_mtk = strdup(buf);
			args |= ARG_RAMDISK_MTK;
			continue;
		}
		if (!(args & ARG_SECOND_MTK) && !strcmp(c, "second_mtk")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("second_mtk");
			second_mtk = strdup(buf);
			args |= ARG_SECOND_MTK;
			continue;
		}
		if (!(args & ARG_DT_MTK) && !strcmp(c, "dt_mtk")) {
			if (read_string_from_file(file, buf, sizeof(buf)))
				continue;
			foundfile("dt_mtk");
			dt_mtk = strdup(buf);
			args |= ARG_DT_MTK;
			continue;
		}
#endif
	}

	closedir(dfd);

	info |= args;

	goto modify;

update:
	if (!input)
		specify("an input boot image");

	image = load_boot_image(input);
	if (!image && (ret = ENOENT))
		failto("load boot image");

	if (!output)
		output = input;

	/* continue through modify */
modify:
	if (args & ARG_BASE)
		bootimg_set_base(image, base);
	if (args & ARG_KERNEL_OFFSET)
		bootimg_set_offset(image, BOOTIMG_KERNEL, kernel_offset);
	if (args & ARG_RAMDISK_OFFSET)
		bootimg_set_offset(image, BOOTIMG_RAMDISK, ramdisk_offset);
	if (args & ARG_SECOND_OFFSET)
		bootimg_set_offset(image, BOOTIMG_SECOND, second_offset);
	if (args & ARG_TAGS_OFFSET)
		bootimg_set_tags_offset(image, tags_offset);

	if (args & ARG_PAGESIZE
	 && (ret = bootimg_set_pagesize(image, pagesize)))
		failto("set page size");

	if (args & ARG_BOARD
	 && (ret = bootimg_set_board(image, board)))
		failto("set board magic");

	if (args & ARG_OS_VERSION
	 && (ret = bootimg_set_os_version(image, os_version)))
		failto("set OS version");

	if (args & ARG_PATCH_LEVEL
	 && (ret = bootimg_set_patch_level(image, patch_level)))
		failto("set patch level");

	if (args & ARG_CMDLINE
	 && (ret = bootimg_set_cmdline(image, cmdline)))
		failto("set cmdline");

	if (args & ARG_CMDLINE_ARG) {
		for (i = argstart; i < argc; i++) {
			if (strcmp(argv[i], "-a") && strcmp(argv[i], "--arg"))
				continue;
			i++;
			if (!strcmp(argv[i + 1], DELETE_VALUE)) {
				if ((ret = bootimg_set_cmdline_arg(image, argv[i], 0)))
					failto("remove cmdline argument");
			} else {
				if ((ret = bootimg_set_cmdline_arg(image, argv[i], argv[i + 1])))
					failto("set cmdline argument");
			}
			i++;
		}
		info |= INFO_CMDLINE;
	}

	if (args & ARG_KERNEL
	 && (ret = bootimg_load(image, BOOTIMG_KERNEL, kernel)))
		failto("load kernel image");

	if (args & ARG_RAMDISK
	 && (ret = bootimg_load(image, BOOTIMG_RAMDISK, ramdisk)))
		failto("load ramdisk image");

	if (args & ARG_SECOND
	 && (ret = bootimg_load(image, BOOTIMG_SECOND, second)))
		failto("load second image");

	if (args & ARG_DT
	 && (ret = bootimg_load(image, BOOTIMG_DT, dt)))
		failto("load dt image");

#ifndef NO_MTK_SUPPORT
	if (args & ARG_KERNEL_MTK
	 && (ret = bootimg_set_mtk_header(image, BOOTIMG_KERNEL, kernel_mtk)))
		failto("set kernel mtk header");

	if (args & ARG_RAMDISK_MTK
	 && (ret = bootimg_set_mtk_header(image, BOOTIMG_RAMDISK, ramdisk_mtk)))
		failto("set ramdisk mtk header");

	if (args & ARG_SECOND_MTK
	 && (ret = bootimg_set_mtk_header(image, BOOTIMG_SECOND, second_mtk)))
		failto("set second mtk header");

	if (args & ARG_DT_MTK
	 && (ret = bootimg_set_mtk_header(image, BOOTIMG_DT, dt_mtk)))
		failto("set dt mtk header");
#endif

	if (args & ARG_HASH) {
		bootimg_update_hash(image);
		info |= INFO_HASH;
	}

	if (verbose)
		print_boot_info(image, info);

	if ((ret = write_boot_image(image, output)))
		failto("write boot image");

free:
	unset(board);
	unset(os_version);
	unset(patch_level);
	unset(cmdline);
	unset(kernel);
	unset(ramdisk);
	unset(second);
	unset(dt);
#ifndef NO_MTK_SUPPORT
	unset(kernel_mtk);
	unset(ramdisk_mtk);
	unset(second_mtk);
	unset(dt_mtk);
#endif
	free_boot_image(image);
	return ret;
}
