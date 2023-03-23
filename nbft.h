// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * nbft.h
 *
 * Copyright (c) 2021-2022, Dell Inc. or its subsidiaries.  All Rights Reserved.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <ccan/list/list.h>

#define NBFT_SYSFS_PATH		"/sys/firmware/acpi/tables"

struct nbft_file_entry {
	struct list_node node;
	struct nbft_info *nbft;
};

int read_nbft_files(struct list_head *nbft_list, char *path);
void free_nbfts(struct list_head *nbft_list);

extern int discover_from_nbft(nvme_root_t r, char *hostnqn_arg, char *hostid_arg,
			      char *hostnqn_sys, char *hostid_sys,
			      const char *desc, bool connect,
			      const struct nvme_fabrics_config *cfg, char *nbft_path,
			      enum nvme_print_flags flags, bool verbose);

//extern int show_nbft(const char *desc, int argc, char **argv);
