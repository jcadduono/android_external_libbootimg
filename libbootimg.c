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

#include "bootimg.h"
#ifdef ENABLE_SHA
#include "mincrypt/sha.h"
#endif

static byte padding[131072] = { 0, };

static void seek_padding(int fd, int pagesize, uint32_t itemsize)
{
	int pagemask = pagesize - 1;
	int count;

	if ((itemsize & pagemask) == 0)
		return;

	count = pagesize - (itemsize & pagemask);

	lseek(fd, count, SEEK_CUR);
}

static int write_padding(int fd, int pagesize, uint32_t itemsize)
{
	int pagemask = pagesize - 1;
	int count;

	if ((itemsize & pagemask) == 0)
		return 0;

	count = pagesize - (itemsize & pagemask);

	return (write(fd, padding, count) == count) ? 0 : -1;
}

static byte *load_file(const char *file, uint32_t *size)
{
	int sz, fd;
	byte *data;

	fd = open(file, O_RDONLY);
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

int bootimg_set_pagesize(boot_img *image, int pagesize)
{
	switch (pagesize) {
	case 2048: case 4096:
	case 8192: case 16384:
	case 32768: case 65536:
	case 131072:
		image->hdr.pagesize = pagesize;
		return 0;
	case 0:
		image->hdr.pagesize = 2048;
		return 0;
	default:
		return EINVAL;
	}
}

int bootimg_set_board(boot_img *image, const char *board)
{
	memset(&image->hdr.board, 0, BOOT_BOARD_SIZE);

	if (!board) {
		strcpy((char*)image->hdr.board, "");
		return 0;
	}

	if (strlen(board) >= BOOT_BOARD_SIZE)
		return EINVAL;

	strcpy((char*)image->hdr.board, board);

	return 0;
}

static int cmdline_update(boot_img *image,
	const char *arg, const char *val, int delete)
{
	int len, append;
	int larg = 0, lval = 0;
	int in_quot = 0, arg_found = 0;
	char *arg_start = 0, *arg_end = 0, *val_start = 0, *val_end = 0;
	char *str = (char*)image->hdr.cmdline;
	char *c = str;
	if (arg)
		larg = strlen(arg);
	if (val)
		lval = strlen(val);

	len = strlen(str);
	if (!len) { // empty cmdline
		if (delete) // nothing to delete
			goto done;
		goto append_arg;
	}

	for (;; c++) {
		switch (*c) {
		case 0: // end of the line
			in_quot = 0;
			goto parse_arg;
		case ' ':
		case '\t':
			if (in_quot)
				continue;
			if (!arg_start) { // remove unnecessary padding
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
						*c = ' '; // replace tab delimiters with spaces
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
			if (c == str || *(c - 1) != '\\') // skip escaped quotes
				in_quot = !in_quot;
		default:
			if (!arg_start)
				arg_start = c;
			continue;
		}
		// if we reach here, we're at the end of a val or arg has no val
parse_arg:
		if (!arg_start)
			goto next_arg;

		if (val_start)
			val_end = c;
		else
			arg_end = c;

		if (!arg) // no arg means just a cleanup
			goto next_arg;

		if (larg != (arg_end - arg_start)) // does not match size of arg
			goto next_arg;

		if (memcmp(arg_start, arg, larg)) // does not match arg
			goto next_arg;

		arg_found = 1;

		if (delete)
			goto delete_arg;

		if (!lval) { // keep arg, remove value
			if (!val_end) // already no value
				goto next_arg;
			memmove(arg_end, val_end, strlen(val_end) + 1); // move val_end -> null to arg_end
			c = arg_end;
			len -= (val_end - arg_end);
			goto next_arg;
		}

		if (lval == (val_end - val_start)) { // value sizes match
			// well, isn't this convenient!
			memcpy(val_start, val, lval);
			goto next_arg;
		}

		// replace the arg value
		// it's much easier to just delete the argument and append it (cheating, i know ;)!)
		arg_found = 0;
delete_arg:
		// shift the rest of the command line left over the arg
		if (val_end)
			arg_end = val_end;
		if (arg_start > str && *(arg_start - 1) == ' ')
			arg_start--; // remove space before the arg
		memmove(arg_start, arg_end, strlen(arg_end) + 1); // move arg_end -> null to arg_start
		c = arg_start;
		len -= (arg_end - arg_start);
next_arg:
		// we need to reset them
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

	// calculate length required for append
	append = larg;
	if (lval)
		append += lval + 1; // =val
	if (len)
		append++; // space before arg
	append++; // null terminator

	if (len + append > BOOT_ARGS_SIZE)
		goto fail; // can't fit new arg/val on cmdline

	if (len) // add a space
		*(c++) = ' ';

	// add arg
	memcpy(c, arg, larg);
	c += larg;

	if (!lval)
		goto done;

	// add =val
	*(c++) = '=';
	memcpy(c, val, lval);
	c += lval;
done:
	// fill the remaining space with null
	memset(c, 0, BOOT_ARGS_SIZE - (c - str));
	return 0;
fail:
	memset(c, 0, BOOT_ARGS_SIZE - (c - str));
	return E2BIG;
}

int bootimg_set_cmdline(boot_img *image, const char *cmdline)
{
	int len = cmdline ? strlen(cmdline) : 0;

	if (!len) {
		memset(&image->hdr.cmdline, 0, BOOT_ARGS_SIZE);
		return 0;
	}

	if (len > BOOT_ARGS_SIZE - 1)
		return E2BIG;

	strcpy((char*)image->hdr.cmdline, cmdline);
	return cmdline_update(image, 0, 0, 0);
}

int bootimg_set_cmdline_arg(boot_img *image, const char *arg, const char *val)
{
	return cmdline_update(image, arg, val, 0);
}

int bootimg_delete_cmdline_arg(boot_img *image, const char *arg)
{
	return cmdline_update(image, arg, 0, 1);
}

int bootimg_load_kernel(boot_img *image, const char *file)
{
	if (image->kernel)
		free(image->kernel);

	image->ramdisk = 0;
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

int load_boot_image(boot_img *image, const char *file)
{
	int ret, fd, i;
	char magic[BOOT_MAGIC_SIZE];

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return ENOENT;

	for (i = 0; i <= 4096; i++) {
		lseek(fd, i, SEEK_SET);
		read(fd, magic, BOOT_MAGIC_SIZE);
		if (memcmp(magic, BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0)
			break;
	}

	if (i > 4096) {
		ret = EINVAL;
		goto close;
	}

	lseek(fd, i, SEEK_SET);

	ret = EIO;

	image->kernel = 0;
	image->ramdisk = 0;
	image->second = 0;
	image->dt = 0;

	if (read(fd, &image->hdr, sizeof(image->hdr)) != sizeof(image->hdr))
		goto close;

	seek_padding(fd, image->hdr.pagesize, sizeof(image->hdr));

	if (image->hdr.kernel_size) {
		image->kernel = malloc(image->hdr.kernel_size);
		if (read(fd, image->kernel, image->hdr.kernel_size) != image->hdr.kernel_size)
			goto close;
	}

	seek_padding(fd, image->hdr.pagesize, image->hdr.kernel_size);

	if (image->hdr.ramdisk_size) {
		image->ramdisk = malloc(image->hdr.ramdisk_size);
		if (read(fd, image->ramdisk, image->hdr.ramdisk_size) != image->hdr.ramdisk_size)
			goto close;
	}

	seek_padding(fd, image->hdr.pagesize, image->hdr.ramdisk_size);

	if (image->hdr.second_size) {
		image->second = malloc(image->hdr.second_size);
		if (read(fd, image->second, image->hdr.second_size) != image->hdr.second_size)
			goto close;
	}

	seek_padding(fd, image->hdr.pagesize, image->hdr.second_size);

	if (image->hdr.dt_size) {
		image->dt = malloc(image->hdr.dt_size);
		if (read(fd, image->dt, image->hdr.dt_size) != image->hdr.dt_size)
			goto close;
	}

	ret = 0;
close:
	close(fd);
	return ret;
}

int create_boot_image(boot_img *image,
	const char *kernel, const char *ramdisk,
	const char *second, const char *dt,
	const char *board, const char *cmdline,
	int pagesize, uint32_t base,
	uint32_t kernel_offset, uint32_t ramdisk_offset,
	uint32_t second_offset, uint32_t tags_offset)
{
	memset(&image->hdr, 0, sizeof(image->hdr));

	memcpy(&image->hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

	if (kernel_offset == 0)
		kernel_offset = 0x00008000U;
	if (ramdisk_offset == 0)
		ramdisk_offset = 0x01000000U;
	if (second_offset == 0)
		second_offset = 0x00F00000U;
	if (tags_offset == 0)
		tags_offset = 0x00000100U;

	image->hdr.kernel_addr  = base + kernel_offset;
	image->hdr.ramdisk_addr = base + ramdisk_offset;
	image->hdr.second_addr  = base + second_offset;
	image->hdr.tags_addr    = base + tags_offset;

	image->kernel  = 0;
	image->ramdisk = 0;
	image->second  = 0;
	image->dt      = 0;

	if (bootimg_set_pagesize(image, pagesize))
		goto oops;

	if (bootimg_set_board(image, board))
		goto oops;

	if (bootimg_set_cmdline(image, cmdline))
		goto oops;

	if (bootimg_load_kernel(image, kernel))
		goto oops;

	if (bootimg_load_ramdisk(image, ramdisk))
		goto oops;

	if (bootimg_load_second(image, second))
		goto oops;

	if (bootimg_load_dt(image, dt))
		goto oops;

	return 0;
oops:
	free_boot_image(image);
	return EINVAL;
}

int write_boot_image(boot_img *image, const char *file)
{
	int fd;
#ifdef ENABLE_SHA
	const uint8_t* sha;
	SHA_CTX ctx;

	/*
	 * put a hash of the contents in the header so boot images can be
	 * differentiated based on their first 2k.
	 */
	SHA_init(&ctx);
	if (image->kernel) {
		SHA_update(&ctx, image->kernel, image->hdr.kernel_size);
		SHA_update(&ctx, &image->hdr.kernel_size, sizeof(image->hdr.kernel_size));
	}
	if (image->ramdisk) {
		SHA_update(&ctx, image->ramdisk, image->hdr.ramdisk_size);
		SHA_update(&ctx, &image->hdr.ramdisk_size, sizeof(image->hdr.ramdisk_size));
	}
	if (image->second) {
		SHA_update(&ctx, image->second, image->hdr.second_size);
		SHA_update(&ctx, &image->hdr.second_size, sizeof(image->hdr.second_size));
	}
	if (image->dt) {
		SHA_update(&ctx, image->dt, image->hdr.dt_size);
		SHA_update(&ctx, &image->hdr.dt_size, sizeof(image->hdr.dt_size));
	}
	sha = SHA_final(&ctx);
	memcpy(image->hdr.id, sha,
		SHA_DIGEST_SIZE > sizeof(image->hdr.id) ? sizeof(image->hdr.id) : SHA_DIGEST_SIZE);
#endif

	fd = open(file, O_CREAT | O_TRUNC | O_WRONLY, 0666);
	if (fd < 0)
		return EACCES;

	if (write(fd, &image->hdr, sizeof(image->hdr)) != sizeof(image->hdr))
		goto oops;
	if (write_padding(fd, image->hdr.pagesize, sizeof(image->hdr)))
		goto oops;

	if (image->kernel) {
		if (write(fd, image->kernel, image->hdr.kernel_size) != (ssize_t)image->hdr.kernel_size)
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.kernel_size))
			goto oops;
	}

	if (image->ramdisk) {
		if (write(fd, image->ramdisk, image->hdr.ramdisk_size) != (ssize_t)image->hdr.ramdisk_size)
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.ramdisk_size))
			goto oops;
	}

	if (image->second) {
		if (write(fd, image->second, image->hdr.second_size) != (ssize_t)image->hdr.second_size)
			goto oops;
		if (write_padding(fd, image->hdr.pagesize, image->hdr.second_size))
			goto oops;
	}

	if (image->dt) {
		if (write(fd, image->dt, image->hdr.dt_size) != (ssize_t)image->hdr.dt_size)
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
	if (image->kernel)
		free(image->kernel);
	if (image->ramdisk)
		free(image->ramdisk);
	if (image->second)
		free(image->second);
	if (image->dt)
		free(image->dt);
}
