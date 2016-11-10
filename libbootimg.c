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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include "bootimg.h"
#include "mincrypt/sha.h"

/* create new files as 0644 */
#define NEW_FILE_PERMISSIONS (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

/* mingw32-gcc compatibility */
#if defined(_WIN32) || defined(__WIN32__)
#define mkdir(A, B) mkdir(A)
#else
#define O_BINARY 0
#endif

static byte padding[131072] = { 0, };

static void seek_padding(const int fd, const int pagesize, const off_t itemsize)
{
	int count, pagemask = pagesize - 1;

	if ((itemsize & pagemask) == 0)
		return;

	count = pagesize - (itemsize & pagemask);

	lseek(fd, count, SEEK_CUR);
}

static int write_padding(const int fd, const int pagesize, const off_t itemsize)
{
	int count, pagemask = pagesize - 1;

	if ((itemsize & pagemask) == 0)
		return 0;

	count = pagesize - (itemsize & pagemask);

	return (write(fd, padding, count) == count) ? 0 : -1;
}

static byte *load_file(const char *file, uint32_t *size)
{
	int fd;
	off_t sz;
	byte *data;

	fd = open(file, O_RDONLY | O_BINARY);
	if (fd < 0)
		return 0;

	sz = lseek(fd, 0, SEEK_END);
	if (sz < 0)
		goto oops;

	if (lseek(fd, 0, SEEK_SET))
		goto oops;

	data = malloc(sz);
	if (!data)
		goto oops;

	if (read(fd, data, sz) != sz) {
		free(data);
		goto oops;
	}

	close(fd);
	*size = sz;
	return data;
oops:
	close(fd);
	return 0;
}

static int save_file(const char* file, const byte* binary, const uint32_t size)
{
	int fd = open(file, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, NEW_FILE_PERMISSIONS);
	if (fd < 0)
		return EACCES;

	if (!binary || !size)
		goto close;

	if (write(fd, binary, size) != (off_t)size) {
		close(fd);
		return EIO;
	}
close:
	close(fd);
	return 0;
}

byte *bootimg_generate_hash(const boot_img *image)
{
	SHA_CTX ctx;
	byte *hash = calloc(sizeof(byte), BOOT_HASH_SIZE);

	SHA_init(&ctx);

	SHA_update(&ctx, image->kernel, image->hdr.kernel_size);
	SHA_update(&ctx, &image->hdr.kernel_size, sizeof(image->hdr.kernel_size));

	SHA_update(&ctx, image->ramdisk, image->hdr.ramdisk_size);
	SHA_update(&ctx, &image->hdr.ramdisk_size, sizeof(image->hdr.ramdisk_size));

	SHA_update(&ctx, image->second, image->hdr.second_size);
	SHA_update(&ctx, &image->hdr.second_size, sizeof(image->hdr.second_size));

	SHA_update(&ctx, image->dt, image->hdr.dt_size);
	SHA_update(&ctx, &image->hdr.dt_size, sizeof(image->hdr.dt_size));

	memcpy(hash, SHA_final(&ctx), SHA_DIGEST_SIZE);
	return hash;
}

void bootimg_update_hash(boot_img *image)
{
	byte *hash = bootimg_generate_hash(image);
	memcpy(image->hdr.hash, hash, BOOT_HASH_SIZE);
	free(hash);
}

int bootimg_load_kernel(boot_img *image, const char *file)
{
	if (image->kernel)
		free(image->kernel);

	image->kernel = 0;
	image->hdr.kernel_size = 0;

	if (!file)
		return 0;

	image->kernel = load_file(file, &image->hdr.kernel_size);
	return !image->kernel;
}

int bootimg_load_ramdisk(boot_img *image, const char *file)
{
	if (image->ramdisk)
		free(image->ramdisk);

	image->ramdisk = 0;
	image->hdr.ramdisk_size = 0;

	if (!file)
		return 0;

	image->ramdisk = load_file(file, &image->hdr.ramdisk_size);
	return !image->ramdisk;
}

int bootimg_load_second(boot_img *image, const char *file)
{
	if (image->second)
		free(image->second);

	image->second = 0;
	image->hdr.second_size = 0;

	if (!file)
		return 0;

	image->second = load_file(file, &image->hdr.second_size);
	return !image->second;
}

int bootimg_load_dt(boot_img *image, const char *file)
{
	if (image->dt)
		free(image->dt);

	image->dt = 0;
	image->hdr.dt_size = 0;

	if (!file)
		return 0;

	image->dt = load_file(file, &image->hdr.dt_size);
	return !image->dt;
}

int bootimg_save_kernel(const boot_img *image, const char *file)
{
	return save_file(file, image->kernel, image->hdr.kernel_size);
}

int bootimg_save_ramdisk(const boot_img *image, const char *file)
{
	return save_file(file, image->ramdisk, image->hdr.ramdisk_size);
}

int bootimg_save_second(const boot_img *image, const char *file)
{
	return save_file(file, image->second, image->hdr.second_size);
}

int bootimg_save_dt(const boot_img *image, const char *file)
{
	return save_file(file, image->dt, image->hdr.dt_size);
}

int bootimg_set_board(boot_img *image, const char *board)
{
	memset(&image->hdr.board, 0, BOOT_BOARD_SIZE);

	if (!board || !*board)
		return 0;

	if (strlen(board) >= BOOT_BOARD_SIZE)
		return EMSGSIZE;

	strcpy((char*)image->hdr.board, board);

	return 0;
}

static int cmdline_update(boot_img *image,
	const char *arg, const char *val, const int delete)
{
	int append;
	int len = 0, larg = 0, lval = 0, in_quot = 0, arg_found = 0;
	char *arg_start = 0, *arg_end = 0, *val_start = 0, *val_end = 0;
	char *str = (char*)image->hdr.cmdline;
	char *c = str;
	if (arg && *arg)
		larg = strlen(arg);
	if (val && *val)
		lval = strlen(val);

	if (!*str || !(len = strlen(str))) { /* empty cmdline */
		if (delete) /* nothing to delete */
			goto done;
		goto append_arg;
	}

	for (;; c++) {
		switch (*c) {
		case 0: /* end of the line */
			in_quot = 0;
			goto parse_arg;
		case ' ':
		case '\t':
			if (in_quot)
				continue;
			if (!arg_start) { /* remove unnecessary padding */
				switch (*(c + 1)) {
				case 0:
					*c-- = 0;
					len--;
					continue;
				case ' ':
				case '\t':
					break;
				default:
					if (*c == '\t')
						*c = ' '; /* replace tab delimiters with spaces */
					if (c != str)
						continue;
				}
				memmove(c, c + 1, str + len - c);
				c--;
				len--;
				continue;
			}
			goto parse_arg;
		case '=':
			if (!in_quot && arg_start) {
				arg_end = c;
				val_start = c + 1;
			}
			continue;
		case '"':
			if (c == str || *(c - 1) != '\\') /* skip escaped quotes */
				in_quot = !in_quot;
		default:
			if (!arg_start)
				arg_start = c;
			continue;
		}
		/* if we reach here, we're at the end of a val or arg has no val */
parse_arg:
		if (!arg_start)
			goto next_arg;

		if (val_start)
			val_end = c;
		else
			arg_end = c;

		if (!arg) /* no arg means just a cleanup */
			goto next_arg;

		if (larg != (arg_end - arg_start)) /* does not match size of arg */
			goto next_arg;

		if (memcmp(arg_start, arg, larg)) /* does not match arg */
			goto next_arg;

		arg_found = 1;

		if (delete)
			goto delete_arg;

		if (!lval) { /* keep arg, remove value */
			if (!val_end) /* already no value */
				goto next_arg;
			memmove(arg_end, val_end, strlen(val_end) + 1); /* move val_end -> null to arg_end */
			c = arg_end;
			len -= (val_end - arg_end);
			goto next_arg;
		}

		if (lval == (val_end - val_start)) { /* value sizes match */
			/* well, isn't this convenient! */
			memcpy(val_start, val, lval);
			goto next_arg;
		}

		/* replace the arg value */
		/* it's much easier to just delete the argument and append it (cheating, i know ;)!) */
		arg_found = 0;
delete_arg:
		/* shift the rest of the command line left over the arg */
		if (val_end)
			arg_end = val_end;
		if (arg_start > str && *(arg_start - 1) == ' ')
			arg_start--; /* remove space before the arg */
		memmove(arg_start, arg_end, strlen(arg_end) + 1); /* move arg_end -> null to arg_start */
		c = arg_start;
		len -= (arg_end - arg_start);
next_arg:
		/* we need to reset them */
		arg_start = arg_end = val_start = val_end = 0;
		if (!*c) {
			if (delete)
				goto done;
			if (!arg_found)
				goto append_arg;
			goto done;
		}
		c--;
	}
append_arg:
	if (!larg)
		goto done;

	/* calculate length required for append */
	append = larg;
	if (lval)
		append += lval + 1; /* =val */
	if (len)
		append++; /* space before arg */
	append++; /* null terminator */

	if (len + append > BOOT_ARGS_SIZE)
		goto oops; /* can't fit new arg/val on cmdline */

	if (len) /* add a space */
		*(c++) = ' ';

	/* add arg */
	memcpy(c, arg, larg);
	c += larg;

	if (!lval)
		goto done;

	/* add =val */
	*(c++) = '=';
	memcpy(c, val, lval);
	c += lval;
done:
	/* fill the remaining space with null */
	memset(c, 0, BOOT_ARGS_SIZE - (c - str));
	return 0;
oops:
	memset(c, 0, BOOT_ARGS_SIZE - (c - str));
	return EMSGSIZE;
}

int bootimg_set_cmdline_arg(boot_img *image, const char *arg, const char *val)
{
	return cmdline_update(image, arg, val, 0);
}

int bootimg_delete_cmdline_arg(boot_img *image, const char *arg)
{
	return cmdline_update(image, arg, 0, 1);
}

int bootimg_set_cmdline(boot_img *image, const char *cmdline)
{
	if (!cmdline || !*cmdline) {
		memset(&image->hdr.cmdline, 0, BOOT_ARGS_SIZE);
		return 0;
	}

	if (strlen(cmdline) >= BOOT_ARGS_SIZE)
		return EMSGSIZE;

	strcpy((char*)image->hdr.cmdline, cmdline);
	return cmdline_update(image, 0, 0, 0);
}

int bootimg_set_pagesize(boot_img *image, const int pagesize)
{
	switch (pagesize) {
	case 2048: case 4096:
	case 8192: case 16384:
	case 32768: case 65536:
	case 131072:
		image->hdr.pagesize = pagesize;
		return 0;
	case 0:
		image->hdr.pagesize = BOOT_DEFAULT_PAGESIZE;
		return 0;
	default:
		return EINVAL;
	}
}

void bootimg_set_base(boot_img *image, const uint32_t base)
{
	image->base = base;
	image->hdr.kernel_addr  = base + image->kernel_offset;
	image->hdr.ramdisk_addr = base + image->ramdisk_offset;
	image->hdr.second_addr  = base + image->second_offset;
	image->hdr.tags_addr    = base + image->tags_offset;
}

void bootimg_set_kernel_offset(boot_img *image, const uint32_t offset)
{
	image->kernel_offset    = offset;
	image->hdr.kernel_addr  = image->base + offset;
}

void bootimg_set_ramdisk_offset(boot_img *image, const uint32_t offset)
{
	image->ramdisk_offset   = offset;
	image->hdr.ramdisk_addr = image->base + offset;
}

void bootimg_set_second_offset(boot_img *image, const uint32_t offset)
{
	image->second_offset    = offset;
	image->hdr.second_addr  = image->base + offset;
}

void bootimg_set_tags_offset(boot_img *image, const uint32_t offset)
{
	image->tags_offset      = offset;
	image->hdr.tags_addr    = image->base + offset;
}

boot_img *new_boot_image(void)
{
	boot_img *image;

	image = calloc(1, sizeof(*image));
	if (!image)
		return 0;

	memcpy(&image->hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

	bootimg_set_pagesize(image, BOOT_DEFAULT_PAGESIZE);

	image->base = BOOT_DEFAULT_BASE;

	bootimg_set_kernel_offset(image,  BOOT_DEFAULT_KERNEL_OFFSET);
	bootimg_set_ramdisk_offset(image, BOOT_DEFAULT_RAMDISK_OFFSET);
	bootimg_set_second_offset(image,  BOOT_DEFAULT_SECOND_OFFSET);
	bootimg_set_tags_offset(image,    BOOT_DEFAULT_TAGS_OFFSET);

	return image;
}

boot_img *load_boot_image(const char *file)
{
	int fd, i;
	char magic[BOOT_MAGIC_SIZE];
	boot_img *image;

	fd = open(file, O_RDONLY | O_BINARY);
	if (fd < 0)
		return 0;

	for (i = 0; i <= 4096; i++) {
		lseek(fd, i, SEEK_SET);
		read(fd, magic, BOOT_MAGIC_SIZE);
		if (memcmp(magic, BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0)
			break;
	}

	if (i > 4096)
		goto oops;

	lseek(fd, i, SEEK_SET);

	if (!(image = calloc(1, sizeof(*image))))
		return 0;

	if (read(fd, &image->hdr, sizeof(image->hdr)) != sizeof(image->hdr))
		goto oops;

	image->base = image->hdr.kernel_addr - 0x00008000U;
	image->kernel_offset = image->hdr.kernel_addr - image->base;
	image->ramdisk_offset = image->hdr.ramdisk_addr - image->base;
	image->second_offset = image->hdr.second_addr - image->base;
	image->tags_offset = image->hdr.tags_addr - image->base;

	seek_padding(fd, image->hdr.pagesize, sizeof(image->hdr));

	if (image->hdr.kernel_size) {
		image->kernel = malloc(image->hdr.kernel_size);
		if (read(fd, image->kernel, image->hdr.kernel_size) != (off_t)image->hdr.kernel_size)
			goto oops;
	}

	seek_padding(fd, image->hdr.pagesize, image->hdr.kernel_size);

	if (image->hdr.ramdisk_size) {
		image->ramdisk = malloc(image->hdr.ramdisk_size);
		if (read(fd, image->ramdisk, image->hdr.ramdisk_size) != (off_t)image->hdr.ramdisk_size)
			goto oops;
	}

	seek_padding(fd, image->hdr.pagesize, image->hdr.ramdisk_size);

	if (image->hdr.second_size) {
		image->second = malloc(image->hdr.second_size);
		if (read(fd, image->second, image->hdr.second_size) != (off_t)image->hdr.second_size)
			goto oops;
	}

	seek_padding(fd, image->hdr.pagesize, image->hdr.second_size);

	if (image->hdr.dt_size) {
		image->dt = malloc(image->hdr.dt_size);
		if (read(fd, image->dt, image->hdr.dt_size) != (off_t)image->hdr.dt_size)
			goto oops;
	}

	close(fd);
	return image;
oops:
	close(fd);
	return 0;
}

int write_boot_image(const boot_img *image, const char *file)
{
	int fd = open(file, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, NEW_FILE_PERMISSIONS);
	if (fd < 0)
		return EACCES;

	if (write(fd, &image->hdr, sizeof(image->hdr)) != sizeof(image->hdr))
		goto oops;
	if (write_padding(fd, image->hdr.pagesize, sizeof(image->hdr)))
		goto oops;

	if (image->hdr.kernel_size) {
		if (write(fd, image->kernel, image->hdr.kernel_size) != (off_t)image->hdr.kernel_size)
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.kernel_size))
			goto oops;
	}
	if (image->hdr.ramdisk_size) {
		if (write(fd, image->ramdisk, image->hdr.ramdisk_size) != (off_t)image->hdr.ramdisk_size)
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.ramdisk_size))
			goto oops;
	}
	if (image->hdr.second_size) {
		if (write(fd, image->second, image->hdr.second_size) != (off_t)image->hdr.second_size)
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.second_size))
			goto oops;
	}
	if (image->hdr.dt_size) {
		if (write(fd, image->dt, image->hdr.dt_size) != (off_t)image->hdr.dt_size)
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.dt_size))
			goto oops;
	}

	close(fd);
	return 0;
oops:
	close(fd);
	return EIO;
}

void free_boot_image(boot_img *image)
{
	if (!image)
		return;
	if (image->kernel)
		free(image->kernel);
	if (image->ramdisk)
		free(image->ramdisk);
	if (image->second)
		free(image->second);
	if (image->dt)
		free(image->dt);
	free(image);
}
