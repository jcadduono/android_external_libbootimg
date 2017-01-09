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

/* create new files as 0640 */
#define NEW_FILE_PERMISSIONS (S_IRUSR | S_IWUSR | S_IRGRP)

/* mingw32-gcc compatibility */
#ifndef O_BINARY
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

	return (write(fd, padding, count) != count);
}

static byte *load_file(const char *file, size_t *size)
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

static int save_file(const char* file, const byte* binary, const size_t size)
{
	int fd = open(file, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, NEW_FILE_PERMISSIONS);
	if (fd < 0)
		return EACCES;

	if (!binary || !size)
		goto close;

	if (write(fd, binary, size) != (off_t)size) {
		close(fd);
		unlink(file);
		return EIO;
	}
close:
	close(fd);
	return 0;
}

static boot_img_item *get_item(boot_img *image, const byte item)
{
	switch (item) {
	case BOOTIMG_KERNEL:
		return &image->kernel;
	case BOOTIMG_RAMDISK:
		return &image->ramdisk;
	case BOOTIMG_SECOND:
		return &image->second;
	case BOOTIMG_DT:
		return &image->dt;
	}
	return 0;
}

static uint32_t *get_hdr_item_size(boot_img *image, const byte item)
{
	switch (item) {
	case BOOTIMG_KERNEL:
		return &image->hdr.kernel_size;
	case BOOTIMG_RAMDISK:
		return &image->hdr.ramdisk_size;
	case BOOTIMG_SECOND:
		return &image->hdr.second_size;
	case BOOTIMG_DT:
		return &image->hdr.dt_size;
	}
	return 0;
}

byte *bootimg_generate_hash(const boot_img *image)
{
	SHA_CTX ctx;
	byte *hash;

	hash = calloc(sizeof(byte), BOOT_HASH_SIZE);
	if (!hash)
		return 0;

	SHA_init(&ctx);

#ifndef NO_MTK_SUPPORT
	if (image->kernel.mtk_header)
		SHA_update(&ctx, image->kernel.mtk_header, sizeof(boot_mtk_hdr));
#endif
	SHA_update(&ctx, image->kernel.data, image->kernel.size);
	SHA_update(&ctx, &image->hdr.kernel_size, sizeof(image->hdr.kernel_size));

#ifndef NO_MTK_SUPPORT
	if (image->ramdisk.mtk_header)
		SHA_update(&ctx, image->ramdisk.mtk_header, sizeof(boot_mtk_hdr));
#endif
	SHA_update(&ctx, image->ramdisk.data, image->ramdisk.size);
	SHA_update(&ctx, &image->hdr.ramdisk_size, sizeof(image->hdr.ramdisk_size));

#ifndef NO_MTK_SUPPORT
	if (image->second.mtk_header)
		SHA_update(&ctx, image->second.mtk_header, sizeof(boot_mtk_hdr));
#endif
	SHA_update(&ctx, image->second.data, image->second.size);
	SHA_update(&ctx, &image->hdr.second_size, sizeof(image->hdr.second_size));

#ifndef NO_MTK_SUPPORT
	if (image->dt.mtk_header)
		SHA_update(&ctx, image->dt.mtk_header, sizeof(boot_mtk_hdr));
#endif
	SHA_update(&ctx, image->dt.data, image->dt.size);
	SHA_update(&ctx, &image->hdr.dt_size, sizeof(image->hdr.dt_size));

	memcpy(hash, SHA_final(&ctx), SHA_DIGEST_SIZE);
	return hash;
}

int bootimg_update_hash(boot_img *image)
{
	byte *hash = bootimg_generate_hash(image);
	if (!hash)
		return ENOMEM;

	memcpy(image->hdr.hash, hash, BOOT_HASH_SIZE);

	free(hash);
	return 0;
}

int bootimg_load(boot_img *image, const byte item, const char *file)
{
	size_t sz = 0;
	uint32_t *hsz = get_hdr_item_size(image, item);
	boot_img_item *i = get_item(image, item);

	if (!i)
		return EINVAL;

	if (file) {
		byte *data = load_file(file, &sz);
		if (!data)
			return EACCES;
		i->data = data;
	} else if (i->data) {
		free(i->data);
		i->data = 0;
	} else {
		return 0;
	}

	i->size = sz;
	*hsz = sz;
#ifndef NO_MTK_SUPPORT
	if (i->mtk_header) {
		i->mtk_header->size = sz;
		*hsz += sizeof(boot_mtk_hdr);
	}
#endif

	return 0;
}

int bootimg_save(boot_img *image, const byte item, const char *file)
{
	boot_img_item *i = get_item(image, item);

	if (!i)
		return EINVAL;

	return save_file(file, i->data, i->size);
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

int bootimg_set_cmdline_arg(boot_img *image, const char *arg, const char *val)
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
		if (!val) /* nothing to delete */
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

		if (!val) /* delete arg if value is null */
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
			if (!val)
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

int bootimg_set_cmdline(boot_img *image, const char *cmdline)
{
	memset(&image->hdr.cmdline, 0, BOOT_ARGS_SIZE);

	if (!cmdline || !*cmdline)
		return 0;

	if (strlen(cmdline) >= BOOT_ARGS_SIZE)
		return EMSGSIZE;

	strcpy((char*)image->hdr.cmdline, cmdline);

	return 0;
}

#ifndef NO_MTK_SUPPORT
static boot_mtk_hdr *new_mtk_header(void)
{
	boot_mtk_hdr *hdr = malloc(sizeof(boot_mtk_hdr));
	if (!hdr)
		return 0;

	memcpy(&hdr->magic, BOOT_MTK_HDR_MAGIC, BOOT_MTK_HDR_MAGIC_SIZE);
	hdr->size = 0;
	memset(&hdr->string, 0, BOOT_MTK_HDR_STRING_SIZE);
	memset(&hdr->padding, 0xFF, BOOT_MTK_HDR_PADDING_SIZE);

	return hdr;
}

int bootimg_set_mtk_header(boot_img *image, const byte item, const char *string)
{
	boot_mtk_hdr *hdr;
	boot_img_item *i = get_item(image, item);

	if (!i)
		return EINVAL;

	hdr = i->mtk_header;

	if (!string) {
		if (hdr) {
			uint32_t *sz = get_hdr_item_size(image, item);
			*sz = hdr->size;
			free(hdr);
			i->mtk_header = 0;
		}
		return 0;
	}

	if (strlen(string) >= BOOT_MTK_HDR_STRING_SIZE)
		return EMSGSIZE;

	if (hdr) {
		memset(&hdr->string, 0, BOOT_MTK_HDR_STRING_SIZE);
	} else {
		uint32_t *sz = get_hdr_item_size(image, item);

		hdr = i->mtk_header = new_mtk_header();
		if (!hdr)
			return ENOMEM;
		hdr->size = *sz;
		if (sz)
			*sz += sizeof(boot_mtk_hdr);
	}

	strcpy((char*)hdr->string, string);

	return 0;
}
#endif

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
	image->hdr.kernel_addr  = base + image->kernel.offset;
	image->hdr.ramdisk_addr = base + image->ramdisk.offset;
	image->hdr.second_addr  = base + image->second.offset;
	image->hdr.tags_addr    = base + image->tags_offset;
}

void bootimg_set_offset(boot_img *image, const byte item, const uint32_t offset)
{
	boot_img_item *i = get_item(image, item);
	if (!i)
		return;

	i->offset = offset;

	switch (item) {
	case BOOTIMG_KERNEL:
		image->hdr.kernel_addr = image->base + offset;
		break;
	case BOOTIMG_RAMDISK:
		image->hdr.ramdisk_addr = image->base + offset;
		break;
	case BOOTIMG_SECOND:
		image->hdr.second_addr = image->base + offset;
		break;
	}
}

void bootimg_set_tags_offset(boot_img *image, const uint32_t offset)
{
	image->tags_offset = offset;
	image->hdr.tags_addr = image->base + offset;
}

boot_img *new_boot_image(void)
{
	boot_img *image;

	image = calloc(1, sizeof(boot_img));
	if (!image)
		return 0;

	memcpy(&image->hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

	bootimg_set_pagesize(image, BOOT_DEFAULT_PAGESIZE);

	image->base = BOOT_DEFAULT_BASE;

	bootimg_set_offset(image, BOOTIMG_KERNEL,  BOOT_DEFAULT_KERNEL_OFFSET);
	bootimg_set_offset(image, BOOTIMG_RAMDISK, BOOT_DEFAULT_RAMDISK_OFFSET);
	bootimg_set_offset(image, BOOTIMG_SECOND,  BOOT_DEFAULT_SECOND_OFFSET);
	bootimg_set_tags_offset(image, BOOT_DEFAULT_TAGS_OFFSET);

	return image;
}

/* all freeing after errors is done by the calling function */
static int read_boot_image_item(boot_img *image, int fd, const byte item)
{
#ifndef NO_MTK_SUPPORT
	char magic[BOOT_MTK_HDR_MAGIC_SIZE];
#endif
	size_t sz;
	boot_img_item *i = get_item(image, item);

	if (!i)
		return EINVAL;

	sz = *get_hdr_item_size(image, item);
	if (!sz)
		return 0; /* item is empty */

#ifndef NO_MTK_SUPPORT
	if (sz < sizeof(boot_mtk_hdr))
		goto read_item; /* too small to contain a mtk header */

	/* check for mtk magic */
	read(fd, magic, BOOT_MTK_HDR_MAGIC_SIZE);
	lseek(fd, (off_t)-sizeof(magic), SEEK_CUR);
	if (memcmp(magic, BOOT_MTK_HDR_MAGIC, sizeof(magic)))
		goto read_item; /* not an mtk header */

	/* allocate the mtk header */
	i->mtk_header = malloc(sizeof(boot_mtk_hdr));
	if (!i->mtk_header)
		return ENOMEM;

	/* read the mtk header from the fd */
	if (read(fd, i->mtk_header, sizeof(boot_mtk_hdr)) != sizeof(boot_mtk_hdr))
		return EIO;

	if (i->mtk_header->size != (sz - sizeof(boot_mtk_hdr)))
		return EINVAL;

	sz = i->mtk_header->size;

read_item:
#endif
	i->size = sz;

	/* allocate the item's data */
	i->data = malloc(i->size);
	if (!i->data)
		return ENOMEM;

	/* read the item from the fd */
	if (read(fd, i->data, i->size) != (off_t)i->size)
		return EIO;

	return 0;
}

boot_img *load_boot_image(const char *file)
{
	int fd, i = 0, j = 0, chromeos = 0;
	char magic[BOOT_MAGIC_SIZE];
	boot_img *image = 0;

	fd = open(file, O_RDONLY | O_BINARY);
	if (fd < 0)
		return 0;

search:
	for (i = 0; i <= 65536; i += 512) {
		lseek(fd, j + i, SEEK_SET);
		if (!read(fd, magic, BOOT_MAGIC_SIZE))
			break; /* end of file */
		if (!memcmp(magic, BOOT_MAGIC, BOOT_MAGIC_SIZE))
			goto found;
		if (!memcmp(magic, BOOT_MAGIC_CHROMEOS, BOOT_MAGIC_SIZE)) {
			chromeos = 1;
			j += 65536;
			goto search;
		}
	}

	/* no android boot image magic found */
	goto oops;

found:
	lseek(fd, j + i, SEEK_SET);

	image = calloc(1, sizeof(boot_img));
	if (!image)
		goto oops;

	if (chromeos)
		image->chromeos = 1;

	if (read(fd, &image->hdr, sizeof(boot_img_hdr)) != sizeof(boot_img_hdr))
		goto oops;

	image->base = image->hdr.kernel_addr - 0x00008000U;
	image->kernel.offset = image->hdr.kernel_addr - image->base;
	image->ramdisk.offset = image->hdr.ramdisk_addr - image->base;
	image->second.offset = image->hdr.second_addr - image->base;
	image->tags_offset = image->hdr.tags_addr - image->base;

	seek_padding(fd, image->hdr.pagesize, sizeof(boot_img_hdr));

	if (image->hdr.kernel_size
	 && read_boot_image_item(image, fd, BOOTIMG_KERNEL))
		goto oops;

	seek_padding(fd, image->hdr.pagesize, image->hdr.kernel_size);

	if (image->hdr.ramdisk_size
	 && read_boot_image_item(image, fd, BOOTIMG_RAMDISK))
		goto oops;

	seek_padding(fd, image->hdr.pagesize, image->hdr.ramdisk_size);

	if (image->hdr.second_size
	 && read_boot_image_item(image, fd, BOOTIMG_SECOND))
		goto oops;

	seek_padding(fd, image->hdr.pagesize, image->hdr.second_size);

	if (image->hdr.dt_size
	 && read_boot_image_item(image, fd, BOOTIMG_DT))
		goto oops;

	close(fd);
	return image;
oops:
	close(fd);
	free_boot_image(image);
	return 0;
}

static int write_boot_image_item(boot_img *image, int fd, const byte item)
{
	size_t sz;
	boot_img_item *i = get_item(image, item);

	if (!i)
		return EINVAL;

#ifndef NO_MTK_SUPPORT
	if (i->mtk_header) {
		/* write the mtk header to the fd */
		if (write(fd, i->mtk_header, sizeof(boot_mtk_hdr)) != sizeof(boot_mtk_hdr))
			return EIO;
		sz = i->mtk_header->size;
	} else {
		sz = *get_hdr_item_size(image, item);
	}
#else
	sz = *get_hdr_item_size(image, item);
#endif

	if (!sz)
		return 0;

	if (write(fd, i->data, sz) != (off_t)sz)
		return EIO;

	return 0;
}

int write_boot_image(boot_img *image, const char *file)
{
	int fd = open(file, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, NEW_FILE_PERMISSIONS);
	if (fd < 0)
		return EACCES;

	if (write(fd, &image->hdr, sizeof(boot_img_hdr)) != sizeof(boot_img_hdr))
		goto oops;
	if (write_padding(fd, image->hdr.pagesize, sizeof(boot_img_hdr)))
		goto oops;

	if (image->hdr.kernel_size) {
		if (write_boot_image_item(image, fd, BOOTIMG_KERNEL))
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.kernel_size))
			goto oops;
	}
	if (image->hdr.ramdisk_size) {
		if (write_boot_image_item(image, fd, BOOTIMG_RAMDISK))
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.ramdisk_size))
			goto oops;
	}
	if (image->hdr.second_size) {
		if (write_boot_image_item(image, fd, BOOTIMG_SECOND))
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.second_size))
			goto oops;
	}
	if (image->hdr.dt_size) {
		if (write_boot_image_item(image, fd, BOOTIMG_DT))
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.dt_size))
			goto oops;
	}

	close(fd);
	return 0;
oops:
	close(fd);
	unlink(file);
	return EIO;
}

void free_boot_image(boot_img *image)
{
	if (!image)
		return;

	if (image->kernel.data)
		free(image->kernel.data);
	if (image->ramdisk.data)
		free(image->ramdisk.data);
	if (image->second.data)
		free(image->second.data);
	if (image->dt.data)
		free(image->dt.data);

#ifndef NO_MTK_SUPPORT
	if (image->kernel.mtk_header)
		free(image->kernel.mtk_header);
	if (image->ramdisk.mtk_header)
		free(image->ramdisk.mtk_header);
	if (image->second.mtk_header)
		free(image->second.mtk_header);
	if (image->dt.mtk_header)
		free(image->dt.mtk_header);
#endif

	free(image);
}
