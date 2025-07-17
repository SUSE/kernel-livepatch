/*
 * livepatch_bsc1238912
 *
 * Fix for CVE-2025-21772, bsc#1238912
 *
 *  Upstream commit:
 *  80e648042e51 ("partitions: mac: fix handling of bogus partition table")
 *
 *  SLE12-SP5 commit:
 *  9071ce6b9dd391e8e6b51ac56d15c4e697ed0180
 *
 *  SLE15-SP3 commit:
 *  3153466afa96fd8287c36fa0d6cc6115e0284f39
 *
 *  SLE15-SP4 and -SP5 commit:
 *  0fbb2d1dc594a84ab78d84f7b31db6aa8e680c95
 *
 *  SLE15-SP6 commit:
 *  9b6ced4af36225c238ebe710572847699e165d4e
 *
 *  SLE MICRO-6-0 commit:
 *  9b6ced4af36225c238ebe710572847699e165d4e
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


/* klp-ccp: from block/partitions/check.h */
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>

struct parsed_partitions {
	struct block_device *bdev;
	char name[BDEVNAME_SIZE];
	struct {
		sector_t from;
		sector_t size;
		int flags;
		bool has_info;
		struct partition_meta_info info;
	} *parts;
	int next;
	int limit;
	bool access_beyond_eod;
	char *pp_buf;
};

static inline void *read_part_sector(struct parsed_partitions *state,
				     sector_t n, Sector *p)
{
	if (n >= get_capacity(state->bdev->bd_disk)) {
		state->access_beyond_eod = true;
		return NULL;
	}
	return read_dev_sector(state->bdev, n, p);
}

static inline void
put_partition(struct parsed_partitions *p, int n, sector_t from, sector_t size)
{
	if (n < p->limit) {
		char tmp[1 + BDEVNAME_SIZE + 10 + 1];

		p->parts[n].from = from;
		p->parts[n].size = size;
		snprintf(tmp, sizeof(tmp), " %s%d", p->name, n);
		strlcat(p->pp_buf, tmp, PAGE_SIZE);
	}
}

/* klp-ccp: from block/partitions/mac.h */
#define MAC_PARTITION_MAGIC	0x504d

struct mac_partition {
	__be16	signature;	/* expected to be MAC_PARTITION_MAGIC */
	__be16	res1;
	__be32	map_count;	/* # blocks in partition map */
	__be32	start_block;	/* absolute starting block # of partition */
	__be32	block_count;	/* number of blocks in partition */
	char	name[32];	/* partition name */
	char	type[32];	/* string type description */
	__be32	data_start;	/* rel block # of first data block */
	__be32	data_count;	/* number of data blocks */
	__be32	status;		/* partition status bits */
	__be32	boot_start;
	__be32	boot_size;
	__be32	boot_load;
	__be32	boot_load2;
	__be32	boot_entry;
	__be32	boot_entry2;
	__be32	boot_cksum;
	char	processor[16];	/* identifies ISA of boot */
	/* there is more stuff after this that we don't need */
};

#define MAC_DRIVER_MAGIC	0x4552

struct mac_driver_desc {
	__be16	signature;	/* expected to be MAC_DRIVER_MAGIC */
	__be16	block_size;
	__be32	block_count;
    /* ... more stuff */
};

/* klp-ccp: from block/partitions/mac.c */
int klpp_mac_partition(struct parsed_partitions *state)
{
	Sector sect;
	unsigned char *data;
	int slot, blocks_in_map;
	unsigned secsize, datasize, partoffset;
#ifdef CONFIG_PPC_PMAC
#error "klp-ccp: non-taken branch"
#endif
	struct mac_partition *part;
	struct mac_driver_desc *md;

	/* Get 0th block and look at the first partition map entry. */
	md = read_part_sector(state, 0, &sect);
	if (!md)
		return -1;
	if (be16_to_cpu(md->signature) != MAC_DRIVER_MAGIC) {
		put_dev_sector(sect);
		return 0;
	}
	secsize = be16_to_cpu(md->block_size);
	put_dev_sector(sect);

	/*
	 * If the "block size" is not a power of 2, things get weird - we might
	 * end up with a partition straddling a sector boundary, so we wouldn't
	 * be able to read a partition entry with read_part_sector().
	 * Real block sizes are probably (?) powers of two, so just require
	 * that.
	 */
	if (!is_power_of_2(secsize))
		return -1;
	datasize = round_down(secsize, 512);
	data = read_part_sector(state, datasize / 512, &sect);
	if (!data)
		return -1;
	partoffset = secsize % 512;
	if (partoffset + sizeof(*part) > datasize) {
		put_dev_sector(sect);
		return -1;
	}
	part = (struct mac_partition *) (data + partoffset);
	if (be16_to_cpu(part->signature) != MAC_PARTITION_MAGIC) {
		put_dev_sector(sect);
		return 0;		/* not a MacOS disk */
	}
	blocks_in_map = be32_to_cpu(part->map_count);
	if (blocks_in_map < 0 || blocks_in_map >= DISK_MAX_PARTS) {
		put_dev_sector(sect);
		return 0;
	}

	if (blocks_in_map >= state->limit)
		blocks_in_map = state->limit - 1;

	strlcat(state->pp_buf, " [mac]", PAGE_SIZE);
	for (slot = 1; slot <= blocks_in_map; ++slot) {
		int pos = slot * secsize;
		put_dev_sector(sect);
		data = read_part_sector(state, pos/512, &sect);
		if (!data)
			return -1;
		part = (struct mac_partition *) (data + pos%512);
		if (be16_to_cpu(part->signature) != MAC_PARTITION_MAGIC)
			break;
		put_partition(state, slot,
			be32_to_cpu(part->start_block) * (secsize/512),
			be32_to_cpu(part->block_count) * (secsize/512));

		if (!strncasecmp(part->type, "Linux_RAID", 10))
			state->parts[slot].flags = ADDPART_FLAG_RAID;
#ifdef CONFIG_PPC_PMAC
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_PPC_PMAC */
	}
#ifdef CONFIG_PPC_PMAC
#error "klp-ccp: non-taken branch"
#endif
	put_dev_sector(sect);
	strlcat(state->pp_buf, "\n", PAGE_SIZE);
	return 1;
}


#include "livepatch_bsc1238912.h"

