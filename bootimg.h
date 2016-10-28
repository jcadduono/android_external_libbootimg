/* tools/mkbootimg/bootimg.h (modified for libbootimg)
**
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

#include <stdint.h>

#ifndef _BOOT_IMAGE_H_
#define _BOOT_IMAGE_H_

typedef struct boot_img_hdr boot_img_hdr;
typedef struct boot_img boot_img;
typedef unsigned char byte;

#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8
#define BOOT_BOARD_SIZE 16
#define BOOT_ARGS_SIZE 512
#define BOOT_EXTRA_ARGS_SIZE 1024

struct boot_img_hdr
{
	uint8_t magic[BOOT_MAGIC_SIZE];

	uint32_t kernel_size;  /* size in bytes */
	uint32_t kernel_addr;  /* physical load addr */

	uint32_t ramdisk_size; /* size in bytes */
	uint32_t ramdisk_addr; /* physical load addr */

	uint32_t second_size;  /* size in bytes */
	uint32_t second_addr;  /* physical load addr */

	uint32_t tags_addr;    /* physical addr for kernel tags */
	uint32_t pagesize;     /* flash page size we assume */
	uint32_t dt_size;      /* device tree in bytes */
	uint32_t unused;       /* future expansion: should be 0 */

	uint8_t board[BOOT_BOARD_SIZE]; /* asciiz product name */

	uint8_t cmdline[BOOT_ARGS_SIZE];

	uint32_t id[8]; /* timestamp / checksum / sha1 / etc */

	/* Supplemental command line data; kept here to maintain
	* binary compatibility with older versions of mkbootimg */
	uint8_t extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
} __attribute__((packed));

struct boot_img
{
	boot_img_hdr hdr;  /* the boot image header    */
	byte *kernel;      /* pointer to kernel image  */
	byte *ramdisk;     /* pointer to ramdisk image */
	byte *second;      /* pointer to second image  */
	byte *dt;          /* pointer to dt image      */
};

/*
** +-----------------+ 
** | boot header     | 1 page
** +-----------------+
** | kernel          | n pages  
** +-----------------+
** | ramdisk         | m pages  
** +-----------------+
** | second stage    | o pages
** +-----------------+
** | device tree     | p pages
** +-----------------+
**
** n = (kernel_size + pagesize - 1) / pagesize
** m = (ramdisk_size + pagesize - 1) / pagesize
** o = (second_size + pagesize - 1) / pagesize
** p = (dt_size + pagesize - 1) / pagesize
**
** 0. all entities are pagesize aligned in flash
** 1. kernel and ramdisk are required (size != 0)
** 2. second is optional (second_size == 0 -> no second)
** 3. load each element (kernel, ramdisk, second) at
**    the specified physical address (kernel_addr, etc)
** 4. prepare tags at tag_addr.  kernel_args[] is
**    appended to the kernel commandline in the tags.
** 5. r0 = 0, r1 = MACHINE_TYPE, r2 = tags_addr
** 6. if second_size != 0: jump to second_addr
**    else: jump to kernel_addr
*/

int bootimg_set_pagesize(boot_img *image, int pagesize);
int bootimg_set_board(boot_img *image, const char *board);
int bootimg_set_cmdline(boot_img *image, const char *cmdline);
int bootimg_load_kernel(boot_img *image, const char *file);
int bootimg_load_ramdisk(boot_img *image, const char *file);
int bootimg_load_second(boot_img *image, const char *file);
int bootimg_load_dt(boot_img *image, const char *file);

int create_boot_image(boot_img *image,
	const char *kernel, const char *ramdisk,
	const char *second, const char *dt,
	const char *board, const char *cmdline,
	int pagesize, uint32_t base,
	uint32_t kernel_offset, uint32_t ramdisk_offset,
	uint32_t second_offset, uint32_t tags_offset);

int load_boot_image(boot_img *image, const char *file);

int write_boot_image(boot_img *image, const char *file);

void free_boot_image(boot_img *image);

#endif
