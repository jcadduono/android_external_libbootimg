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

typedef unsigned char byte;

#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_CHROMEOS "CHROMEOS"
#define BOOT_MAGIC_SIZE 8
#define BOOT_BOARD_SIZE 16
#define BOOT_ARGS_SIZE 512
#define BOOT_EXTRA_ARGS_SIZE 1024
#define BOOT_HASH_SIZE 20
#define BOOT_RESERVED_SIZE 12

#ifndef NO_MTK_SUPPORT
#define BOOT_MTK_HDR_MAGIC "\x88\x16\x88\x58"
#define BOOT_MTK_HDR_MAGIC_SIZE 4
#define BOOT_MTK_HDR_STRING_SIZE 32
#define BOOT_MTK_HDR_PADDING_SIZE 472
#endif

/* defaults when creating a new boot image */
#define BOOT_DEFAULT_PAGESIZE       2048
#define BOOT_DEFAULT_BASE           0x10000000U
#define BOOT_DEFAULT_KERNEL_OFFSET  0x00008000U
#define BOOT_DEFAULT_RAMDISK_OFFSET 0x01000000U
#define BOOT_DEFAULT_SECOND_OFFSET  0x00F00000U
#define BOOT_DEFAULT_TAGS_OFFSET    0x00000100U

/* the header of an Android boot image
 * this is the beginning of all valid images */
typedef struct boot_img_hdr
{
	byte magic[BOOT_MAGIC_SIZE];

	uint32_t kernel_size;  /* size in bytes */
	uint32_t kernel_addr;  /* physical load addr */

	uint32_t ramdisk_size; /* size in bytes including mtk header if applicable */
	uint32_t ramdisk_addr; /* physical load addr */

	uint32_t second_size;  /* size in bytes */
	uint32_t second_addr;  /* physical load addr */

	uint32_t tags_addr;    /* physical addr for kernel tags */
	uint32_t pagesize;     /* flash page size we assume     */
	uint32_t dt_size;      /* device tree size in bytes     */
	uint32_t unused;       /* future expansion: should be 0 */

	byte board[BOOT_BOARD_SIZE];  /* asciiz product name */

	byte cmdline[BOOT_ARGS_SIZE]; /* kernel command line */

	byte hash[BOOT_HASH_SIZE]; /* sha1 (kernel + ramdisk + second + dt) */

	byte reserved[BOOT_RESERVED_SIZE]; /* modification timestamp? */

	/* Supplemental command line data; kept here to maintain
	* binary compatibility with older versions of mkbootimg */
	byte extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
} __attribute__((packed)) boot_img_hdr;

#ifndef NO_MTK_SUPPORT
/* a pointless header prepended to all the objects embedded
 * within the Android boot image on some MediaTek devices, shame! */
typedef struct boot_mtk_hdr
{
	byte magic[BOOT_MTK_HDR_MAGIC_SIZE];

	uint32_t size; /* size of content after header in bytes */

	byte string[BOOT_MTK_HDR_STRING_SIZE]; /* KERNEL/ROOTFS/RECOVERY */

	byte padding[BOOT_MTK_HDR_PADDING_SIZE]; /* padding of FF */
} __attribute__((packed)) boot_mtk_hdr;
#endif

/* an item embedded in the Android boot image, ex. kernel/ramdisk/second/dt
 * this is not an actual layout */
typedef struct boot_img_item
{
#ifndef NO_MTK_SUPPORT
	boot_mtk_hdr *mtk_header;
#endif
	byte *data;

	size_t size;

	uint32_t offset;
} boot_img_item;

/* a container struct for working with Android boot images
 * this is not an actual layout */
typedef struct boot_img
{
	boot_img_hdr hdr;      /* the boot image header */

	boot_img_item kernel;  /* kernel image struct   */
	boot_img_item ramdisk; /* ramdisk image struct  */
	boot_img_item second;  /* second image struct   */
	boot_img_item dt;      /* dt image struct       */

	uint32_t base;         /* base location offsets are relative to */
	uint32_t tags_offset;  /* offset of kernel tags */

	unsigned chromeos:1;
} boot_img;

/*
** +-----------------+ 
** | boot header     | 1 page
** +-----------------+
** | [ mtk header ]  |
** | kernel          | n pages  
** +-----------------+
** | [ mtk header ]  |
** | ramdisk         | m pages  
** +-----------------+
** | [ mtk header ]  |
** | second stage    | o pages
** +-----------------+
** | [ mtk header ]  |
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
** 7. mtk headers are only used in some mediatek devices.
**    they can be prepended to any item in the boot image
**    and are also added to the size of each item
**    (+512 bytes) before the page alignment is calculated.
*/

/* boot image items (const byte item) */
enum {
	BOOTIMG_KERNEL = 1,
	BOOTIMG_RAMDISK,
	BOOTIMG_SECOND,
	BOOTIMG_DT
};

byte *bootimg_generate_hash(const boot_img *image);
int bootimg_update_hash(boot_img *image);

int bootimg_load(boot_img *image, const byte item, const char *file);

int bootimg_save(boot_img *image, const byte item, const char *file);

int bootimg_set_board(boot_img *image, const char *board);

int bootimg_set_cmdline(boot_img *image, const char *cmdline);
/* a null val will delete the arg from the cmdline */
int bootimg_set_cmdline_arg(boot_img *image, const char *arg, const char *val);

#ifndef NO_MTK_SUPPORT
int bootimg_set_mtk_header(boot_img *image, const byte item, const char *string);
#endif

int bootimg_set_pagesize(boot_img *image, const int pagesize);

void bootimg_set_base(boot_img *image, const uint32_t base);
void bootimg_set_offset(boot_img *image, const byte item, const uint32_t offset);
void bootimg_set_tags_offset(boot_img *image, const uint32_t offset);

boot_img *new_boot_image(void);

boot_img *load_boot_image(const char *file);

int write_boot_image(boot_img *image, const char *file);

void free_boot_image(boot_img *image);

#endif
