/*
 * livepatch_bsc1179877
 *
 * Fix for CVE-2020-29660 and CVE-2020-29661, bsc#1179877
 *
 *  Upstream commits:
 *  c8bcd9c5be24 ("tty: Fix ->session locking")
 *  54ffccbf053b ("tty: Fix ->pgrp locking in tiocspgrp()")
 *
 *  SLE12-SP2 and -SP3 commits:
 *  1cc3fb381cbb863d6905208cc78026f28cbc28de
 *  8ab07a963bcc577100f821a3ffdc5de6db6e2c7c
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  a59c61c4f55d549279d5d5ae24999564ab7ad8fb
 *  3de7edb960884db8906fc556a12413fbafe475dd
 *
 *  SLE15-SP2 commits:
 *  a9a2af9464b79bbdd980609fe04eb8f3a5b4233c
 *  c18ac30aac9ade995c81cef78b77a959f96a7da9
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#include <linux/kernel.h>
#include <linux/module.h>
#include "bsc1179877.h"

int livepatch_bsc1179877_init(void)
{
	int r;

	r = livepatch_bsc1179877_tty_io_init();
	if (r)
		return r;

	r = livepatch_bsc1179877_tty_jobctrl_init();
	return r;
}
