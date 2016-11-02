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
	MODE_CREATE,
	MODE_UPDATE,
	MODE_INFO
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

static char *basename(char const *path)
{
	const char *s = strrchr(path, '/');
	if (!s) {
		return strdup(path);
	} else {
		return strdup(s + 1);
	}
}

/* args set by user in command */
enum
{
	ARG_BOARD           = 1 <<  0,
	ARG_CMDLINE         = 1 <<  1,
	ARG_PAGESIZE        = 1 <<  2,
	ARG_BASE            = 1 <<  3,
	ARG_KERNEL_OFFSET   = 1 <<  4,
	ARG_RAMDISK_OFFSET  = 1 <<  5,
	ARG_SECOND_OFFSET   = 1 <<  6,
	ARG_TAGS_OFFSET     = 1 <<  7,
	ARG_KERNEL          = 1 <<  8,
	ARG_RAMDISK         = 1 <<  9,
	ARG_SECOND          = 1 << 10,
	ARG_DT              = 1 << 11,
};

/* match arg flags (for verbose output) */
enum
{
	INFO_MAGIC          = 1 <<  0,
	INFO_CMDLINE        = 1 <<  1,
	INFO_PAGESIZE       = 1 <<  2,
	INFO_BASE           = 1 <<  3,
	INFO_KERNEL_OFFSET  = 1 <<  4,
	INFO_RAMDISK_OFFSET = 1 <<  5,
	INFO_SECOND_OFFSET  = 1 <<  6,
	INFO_TAGS_OFFSET    = 1 <<  7,
	INFO_KERNEL_SIZE    = 1 <<  8,
	INFO_RAMDISK_SIZE   = 1 <<  9,
	INFO_SECOND_SIZE    = 1 << 10,
	INFO_DT_SIZE        = 1 << 11,
};

void print_boot_info(boot_img *image, const unsigned info)
{
	char *hash = bootimg_read_hash(image);

	if (info & INFO_MAGIC)
		LOGV("BOARD_MAGIC \"%s\"", image->hdr.board);
	if (info & INFO_CMDLINE)
		LOGV("BOARD_CMDLINE \"%s\"", image->hdr.cmdline);
	if (info & INFO_PAGESIZE)
		LOGV("BOARD_PAGESIZE %u", image->hdr.pagesize);
	if (info & INFO_BASE)
		LOGV("BOARD_BASE 0x%08X", image->base);
	if (info & INFO_KERNEL_OFFSET)
		LOGV("BOARD_KERNEL_OFFSET 0x%08X", image->kernel_offset);
	if (info & INFO_RAMDISK_OFFSET)
		LOGV("BOARD_RAMDISK_OFFSET 0x%08X", image->ramdisk_offset);
	if (info & INFO_SECOND_OFFSET)
		LOGV("BOARD_SECOND_OFFSET 0x%08X", image->second_offset);
	if (info & INFO_TAGS_OFFSET)
		LOGV("BOARD_TAGS_OFFSET 0x%08X", image->tags_offset);
	if (info & INFO_KERNEL_SIZE)
		LOGV("BOARD_KERNEL_SIZE %u", image->hdr.kernel_size);
	if (info & INFO_RAMDISK_SIZE)
		LOGV("BOARD_RAMDISK_SIZE %u", image->hdr.ramdisk_size);
	if (info & INFO_SECOND_SIZE)
		LOGV("BOARD_SECOND_SIZE %u", image->hdr.second_size);
	if (info & INFO_DT_SIZE)
		LOGV("BOARD_DT_SIZE %u", image->hdr.dt_size);

	LOGV("BOARD_ID_HASH 0x%s", hash);
	free(hash);
}

#define usage(...) { \
	LOGE("Usage: %s [xvcf] [args...]\n", argv[0]); \
	LOGE( \
		" Modes:\n" \
		"  -x, --unpack        - unpack an Android boot image\n" \
		"  -c, --create        - create an Android boot image\n" \
		"  -u, --update        - update an Android boot image\n" \
		"  -v, -vv, --verbose  - print boot image details\n" \
		"\n" \
		" Options: (set value only for create/update mode)\n" \
		"   [ -k,  --kernel \"kernel\"        ]\n" \
		"   [ -r,  --ramdisk \"ramdisk\"      ]\n" \
		"   [ -s,  --second \"second\"        ]\n" \
		"   [ -d,  --dt \"dt.img\"            ]\n" \
		"   [ -m,  --board \"board magic\"    ]\n" \
		"   [ -l,  --cmdline \"boot cmdline\" ]\n" \
		"   [ -p,  --pagesize <size>        ]\n" \
		"   [ -b,  --base <hex>             ]\n" \
		"   [ -ko, --kernel_offset <hex>    ]\n" \
		"   [ -ro, --ramdisk_offset <hex>   ]\n" \
		"   [ -so, --second_offset <hex>    ]\n" \
		"   [ -to, --tags_offset <hex>      ]\n" \
		" Unpack:\n" \
		"     -i,  --input \"boot.img\"\n" \
		"     -o,  --output \"directory\"\n" \
		" Create:\n" \
		"     -o,  --output \"boot.img\"\n" \
		"     -i,  --input \"directory\"\n" \
		" Update:\n" \
		"     -i,  --input \"boot.img\"\n" \
		"   [ -o,  --output \"boot.img\"      ]\n" \
		"   [ -a,  --arg \"cmdline arg\" \"value\" ]\n" \
		"        (use - as value to delete args)\n" \
	); \
	LOGE(__VA_ARGS__); \
	return EINVAL; \
}

#define specify(item) usage("You need to specify an %s!", item)
#define failto(item, err) { LOGE("Failed to %s: %s", item, strerror(err)); return err; }

int main(const int argc, const char** argv)
{
	boot_img *image;
	char *bname, file[PATH_MAX], hex[16];
	const char *c,
		*input = 0, *output = 0,
		*kernel = 0, *ramdisk = 0, *second = 0,
		*dt = 0, *board = 0, *cmdline = 0;
	uint32_t base = 0,
		kernel_offset = 0, ramdisk_offset = 0,
		second_offset = 0, tags_offset = 0;
	int i, argstart,
		pagesize = 0, ret = 0,
		verbose = 0, mode = MODE_NONE;
	unsigned args = 0, info = 0;

	if (argc < 2)
		usage("Not enough arguments!");

	// tar style argument parsing (only valid in first arg)
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

	// handle mode changes so next section can parse args in the right mode
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
			// do nothing, we already handled these args
		} else
		if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--input")) {
			input = argv[++i];
		} else
		if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
			if (mode == MODE_INFO)
				usage("You can't use %s in info mode!", argv[i]);
			output = argv[++i];
		} else
		if (!strcmp(argv[i], "-k") || !strcmp(argv[i], "--kernel")) {
			args |= ARG_KERNEL;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				kernel = argv[++i];
			}
		} else
		if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--ramdisk")) {
			args |= ARG_RAMDISK;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				ramdisk = argv[++i];
			}
		} else
		if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--second")) {
			args |= ARG_SECOND;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				second = argv[++i];
			}
		} else
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--dt")) {
			args |= ARG_DT;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				dt = argv[++i];
			}
		} else
		if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--magic")
		 || !strcmp(argv[i], "--board")) {
			args |= ARG_BOARD;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				board = argv[++i];
			}
		} else
		if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--cmdline")) {
			args |= ARG_CMDLINE;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				cmdline = argv[++i];
			}
		} else
		if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--pagesize")) {
			args |= ARG_PAGESIZE;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				pagesize = strtoul(argv[++i], 0, 10);
				break;
			}
		} else
		if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--base")) {
			args |= ARG_BASE;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				base = strtoul(argv[++i], 0, 16);
			}
		} else
		if (!strcmp(argv[i], "-ko")
		 || !strcmp(argv[i], "--kernel_offset")) {
			args |= ARG_KERNEL_OFFSET;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				kernel_offset = strtoul(argv[++i], 0, 16);
			}
		} else
		if (!strcmp(argv[i], "-ro")
		 || !strcmp(argv[i], "--ramdisk_offset")) {
			args |= ARG_RAMDISK_OFFSET;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				ramdisk_offset = strtoul(argv[++i], 0, 16);
			}
		} else
		if (!strcmp(argv[i], "-so")
		 || !strcmp(argv[i], "--second_offset")) {
			args |= ARG_SECOND_OFFSET;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				second_offset = strtoul(argv[++i], 0, 16);
			}
		} else
		if (!strcmp(argv[i], "-to")
		 || !strcmp(argv[i], "--tags_offset")) {
			args |= ARG_TAGS_OFFSET;
			switch (mode) {
			case MODE_CREATE:
			case MODE_UPDATE:
				tags_offset = strtoul(argv[++i], 0, 16);
			}
		} else
		if (!strcmp(argv[i], "-a")
		 || !strcmp(argv[i], "--arg")) {
			if (mode != MODE_UPDATE)
				usage("You can only use %s in update mode!", argv[i]);
			args |= ARG_CMDLINE;
			i++; // we should handle this in update section
		} else
		{ // if it's not an argument, it's either an input or output
			if (mode == MODE_CREATE) {
				if (!output) {
					output = argv[i];
					continue;
				}
				if (!input) {
					input = argv[i];
					continue;
				}
			} else {
				if (!input) {
					input = argv[i];
					continue;
				}
				if (!output && mode != MODE_INFO) {
					output = argv[i];
					continue;
				}
			}
			usage("Unknown argument: %s", argv[i]);
		}
	}

	if (verbose > 1)
		info = -1; // turn them all on!
	else
		info = args;

	switch (mode) {
	case MODE_UNPACK:
		goto unpack;
	case MODE_INFO:
		goto info;
	case MODE_CREATE:
		goto create;
	case MODE_UPDATE:
		goto update;
	}

	return 0; // this should never be reached

unpack:
	if (!input)
		specify("input boot image");

	if (!output)
		specify("output directory");

	image = load_boot_image(input);
	if (!image)
		failto("load boot image", EINVAL);

	if (mkdir(output, NEW_DIR_PERMISSIONS)) {
		LOGE("Could not create output directory: %s", strerror(errno));
		return errno;
	}

	if (verbose)
		print_boot_info(image, info);

	bname = basename(input);

	if (args & ARG_BOARD || !args) {
		sprintf(file, "%s/%s-board", output, bname);
		write_string_to_file(file, (char*)image->hdr.board);
	}
	if (args & ARG_CMDLINE || !args) {
		sprintf(file, "%s/%s-cmdline", output, bname);
		write_string_to_file(file, (char*)image->hdr.cmdline);
	}
	if (args & ARG_PAGESIZE || !args) {
		sprintf(file, "%s/%s-pagesize", output, bname);
		sprintf(hex, "%u", image->hdr.pagesize);
		write_string_to_file(file, hex);
	}
	if (args & ARG_BASE || !args) {
		sprintf(file, "%s/%s-base", output, bname);
		sprintf(hex, "%08X", image->base);
		write_string_to_file(file, hex);
	}
	if (args & ARG_KERNEL_OFFSET || !args) {
		sprintf(file, "%s/%s-kernel_offset", output, bname);
		sprintf(hex, "%08X", image->kernel_offset);
		write_string_to_file(file, hex);
	}
	if (args & ARG_RAMDISK_OFFSET || !args) {
		sprintf(file, "%s/%s-ramdisk_offset", output, bname);
		sprintf(hex, "%08X", image->ramdisk_offset);
		write_string_to_file(file, hex);
	}
	if (args & ARG_SECOND_OFFSET || !args) {
		sprintf(file, "%s/%s-second_offset", output, bname);
		sprintf(hex, "%08X", image->second_offset);
		write_string_to_file(file, hex);
	}
	if (args & ARG_TAGS_OFFSET || !args) {
		sprintf(file, "%s/%s-tags_offset", output, bname);
		sprintf(hex, "%08X", image->tags_offset);
		write_string_to_file(file, hex);
	}
	if (args & ARG_KERNEL || !args) {
		sprintf(file, "%s/%s-kernel", output, bname);
		bootimg_save_kernel(image, file);
	}
	if (args & ARG_RAMDISK || !args) {
		sprintf(file, "%s/%s-ramdisk", output, bname);
		bootimg_save_ramdisk(image, file);
	}
	if (args & ARG_SECOND || !args) {
		sprintf(file, "%s/%s-second", output, bname);
		bootimg_save_second(image, file);
	}
	if (args & ARG_DT || !args) {
		sprintf(file, "%s/%s-dt", output, bname);
		bootimg_save_dt(image, file);
	}

	free(bname);
	goto free;

info:
	if (!input)
		specify("input boot image");

	image = load_boot_image(input);
	if (!image)
		failto("load boot image", EINVAL);

	if (!args)
		info = -1; // turn them all on!

	print_boot_info(image, info);

	goto free;

create:
	if (!output)
		specify("output boot image");

	image = new_boot_image();

	if (!input)
		goto modify;

	// handle input directory....
	goto modify;

update:
	if (!input)
		specify("input boot image");

	image = load_boot_image(input);
	if (!image)
		failto("load boot image", EINVAL);

	if (!output)
		input = output;

modify:
	if (args & ARG_BASE)
		bootimg_set_base(image, base);
	if (args & ARG_KERNEL_OFFSET)
		bootimg_set_kernel_offset(image, kernel_offset);
	if (args & ARG_RAMDISK_OFFSET)
		bootimg_set_ramdisk_offset(image, ramdisk_offset);
	if (args & ARG_SECOND_OFFSET)
		bootimg_set_second_offset(image, second_offset);
	if (args & ARG_TAGS_OFFSET)
		bootimg_set_tags_offset(image, tags_offset);

	if (args & ARG_PAGESIZE) {
		ret = bootimg_set_pagesize(image, pagesize);
		if (ret) {
			free_boot_image(image);
			failto("set page size", ret);
		}
	}

	if (args & ARG_BOARD) {
		ret = bootimg_set_board(image, board);
		if (ret) {
			free_boot_image(image);
			failto("set board magic", ret);
		}
	}

	if (args & ARG_CMDLINE) {
		ret = bootimg_set_cmdline(image, cmdline);
		if (ret) {
			free_boot_image(image);
			failto("set cmdline", ret);
		}
	}

	if (args & ARG_KERNEL) {
		ret = bootimg_load_kernel(image, kernel);
		if (ret) {
			free_boot_image(image);
			failto("load kernel image", ret);
		}
	}

	if (args & ARG_RAMDISK) {
		ret = bootimg_load_ramdisk(image, ramdisk);
		if (ret) {
			free_boot_image(image);
			failto("load ramdisk image", ret);
		}
	}

	if (args & ARG_SECOND) {
		ret = bootimg_load_second(image, second);
		if (ret) {
			free_boot_image(image);
			failto("load second image", ret);
		}
	}

	if (args & ARG_DT) {
		ret = bootimg_load_dt(image, dt);
		if (ret) {
			free_boot_image(image);
			failto("load dt image", ret);
		}
	}

	bootimg_update_hash(image);

	if (verbose)
		print_boot_info(image, info);

	ret = write_boot_image(image, output);
	if (ret)
		failto("write boot image", ret);

free:
	free_boot_image(image);
	return ret;
}
