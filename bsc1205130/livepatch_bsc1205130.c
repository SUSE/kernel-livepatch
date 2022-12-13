/*
 * livepatch_bsc1205130
 *
 * Fix for CVE-2022-43945, bsc#1205130
 *
 *  Upstream commit:
 *  00b4492686e0 ("NFSD: Protect against send buffer overflow in NFSv2 READDIR")
 *  1242a87da0d8 ("SUNRPC: Fix svcxdr_init_encode's buflen calculation")
 *  401bc1f90874 ("NFSD: Protect against send buffer overflow in NFSv2 READ")
 *  640f87c190e0 ("NFSD: Protect against send buffer overflow in NFSv3 READDIR")
 *  76ce4dcec0dc ("NFSD: Cap rsize_bop result based on send buffer size")
 *  90bfc37b5ab9 ("SUNRPC: Fix svcxdr_init_decode's end-of-buffer calculation")
 *  fa6be9cc6e80 ("NFSD: Protect against send buffer overflow in NFSv3 READ")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  e8c5e22e64e5064cff12ef786c1bfa87e9ee0939
 *  9823c31ff281bfcbc585c3b25c4ed74bf941e58d
 *  a32889cbe0f8399cdf23f5c97fdc3d7b53fbe2de
 *  dc177c94ed6fe8097aaec99d1c732a41c7f99769
 *  23983ca65e94ac9b687541e57ebdf418fde77e2c
 *
 *  SLE15-SP2 and -SP3 commit:
 *  0ed7d192ee31254ece8d00477fcccbec120f28d3
 *  67fc8d9bee46ed501868aa3f470a9250b22ad64b
 *  c183f6af4fb139c31b381a9eb4a24920bc23110f
 *  e93318a3f8b5618afcda871b6d8201466af333a8
 *  4c53ca5c3f1da7acb6db66cbbdc63d5d0a421c36
 *
 *  SLE15-SP4 commit:
 *  0b9aeb43b10e483d037fb60ad185df6816db5f4f
 *  a013c7dc815c7c974336fa9257d6d43f69a7e814
 *  4c5fe4fa6f5b6527d7ada40cc69500b4265c0122
 *  98a8bbf6dfefa962c08a0c7e217465243fb3563f
 *  dd4f72046588520823dd3665df7b30b35cba2509
 *  3808f56ecf1a8f23087533077040db105b35b846
 *  4bf16a8d521faaa6d3ca45e65d7ce53bc72a7247
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

#include "livepatch_bsc1205130.h"

int livepatch_bsc1205130_init(void)
{
	int ret;

	ret = bsc1205130_fs_nfsd_nfs3proc_init();
	if (ret)
		return ret;

	ret = bsc1205130_fs_nfsd_nfs3xdr_init();
	if (ret)
		goto out_nfs3proc;

	ret = bsc1205130_fs_nfsd_nfs4proc_init();
	if (ret)
		goto out_nfs3xdr;

	ret = bsc1205130_fs_nfsd_nfsproc_init();
	if (ret)
		goto out_nfs4proc;

	ret = bsc1205130_fs_nfsd_nfsxdr_init();
	if (ret)
		goto out_nfsproc;

	return 0;

out_nfsproc:
	bsc1205130_fs_nfsd_nfsproc_cleanup();
out_nfs4proc:
	bsc1205130_fs_nfsd_nfs4proc_cleanup();
out_nfs3xdr:
	bsc1205130_fs_nfsd_nfs3xdr_cleanup();
out_nfs3proc:
	bsc1205130_fs_nfsd_nfs3proc_cleanup();

	return ret;
}

void livepatch_bsc1205130_cleanup(void)
{
	bsc1205130_fs_nfsd_nfsxdr_cleanup();
	bsc1205130_fs_nfsd_nfsproc_cleanup();
	bsc1205130_fs_nfsd_nfs4proc_cleanup();
	bsc1205130_fs_nfsd_nfs3xdr_cleanup();
	bsc1205130_fs_nfsd_nfs3proc_cleanup();
}
