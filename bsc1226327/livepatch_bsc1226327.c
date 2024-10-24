/*
 * livepatch_bsc1226327
 *
 * Fix for CVE-2024-35905, bsc#1226327
 *
 *  Upstream commit:
 *  a8d89feba7e5 ("bpf: Check bloom filter map value size")
 *  ecc6a2101840 ("bpf: Protect against int overflow for stack access size")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  1edb341e79e0997d6d4f74b54aaaeb549d94c89c
 *
 *  SLE15-SP6 commit:
 *  72c76c85224ee4c8e51c77d6c407401f6935508d
 *  5fa3c1186f44343ae6130db7f10c5284da78b461
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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

#include "livepatch_bsc1226327.h"
