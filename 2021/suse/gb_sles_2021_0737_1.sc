if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0737.1" );
	script_cve_id( "CVE-2020-29368", "CVE-2020-29374", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-26932" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-31 00:15:00 +0000 (Wed, 31 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0737-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0737-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210737-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0737-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 15 SP1 kernel was updated receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-26930: Fixed an improper error handling in blkback's grant
 mapping (XSA-365 bsc#1181843).

CVE-2021-26931: Fixed an issue where Linux kernel was treating grant
 mapping errors as bugs (XSA-362 bsc#1181753).

CVE-2021-26932: Fixed improper error handling issues in Linux grant
 mapping (XSA-361 bsc#1181747). by remote attackers to read or write
 files via directory traversal in an XCOPY request (bsc#178372).

CVE-2020-29368,CVE-2020-29374: Fixed an issue in copy-on-write
 implementation which could have granted unintended write access because
 of a race condition in a THP mapcount check (bsc#1179660, bsc#1179428).

The following non-security bugs were fixed:

btrfs: Cleanup try_flush_qgroup (bsc#1182047).

btrfs: Do not flush from btrfs_delayed_inode_reserve_metadata
 (bsc#1182047).

btrfs: fix data bytes_may_use underflow with fallocate due to failed
 quota reserve (bsc#1182130)

btrfs: Free correct amount of space in
 btrfs_delayed_inode_reserve_metadata (bsc#1182047).

btrfs: Remove btrfs_inode from btrfs_delayed_inode_reserve_metadata
 (bsc#1182047).

btrfs: Simplify code flow in btrfs_delayed_inode_reserve_metadata
 (bsc#1182047).

btrfs: Unlock extents in btrfs_zero_range in case of errors
 (bsc#1182047).

Drivers: hv: vmbus: Avoid use-after-free in vmbus_onoffer_rescind()
 (git-fixes).

ibmvnic: fix a race between open and reset (bsc#1176855 ltc#187293).

kernel-binary.spec: Add back initrd and image symlink ghosts to filelist
 (bsc#1182140). Fixes: 76a9256314c3 ('rpm/kernel-{source,binary}.spec: do
 not include ghost symlinks (boo#1179082).')

libnvdimm/dimm: Avoid race between probe and available_slots_show()
 (bsc#1170442).

net: bcmgenet: add support for ethtool rxnfc flows (git-fixes).

net: bcmgenet: code movement (git-fixes).

net: bcmgenet: fix mask check in bcmgenet_validate_flow() (git-fixes).

net: bcmgenet: Fix WoL with password after deep sleep (git-fixes).

net: bcmgenet: re-remove bcmgenet_hfb_add_filter (git-fixes).

net: bcmgenet: set Rx mode before starting netif (git-fixes).

net: bcmgenet: use __be16 for htons(ETH_P_IP) (git-fixes).

net: bcmgenet: Use correct I/O accessors (git-fixes).

net: lpc-enet: fix error return code in lpc_mii_init() (git-fixes).

net/mlx4_en: Handle TX error CQE (bsc#1181854).

net: moxa: Fix a potential double 'free_irq()' (git-fixes).

net: sun: fix missing release regions in cas_init_one() (git-fixes).

nvme-multipath: Early exit if no path is available (bsc#1180964).

rpm/post.sh: Avoid purge-kernel for the first installed kernel
 (bsc#1180058)

scsi: target: fix unmap_zeroes_data boolean initialisation (bsc#1163617).

usb: dwc2: Abort transaction after errors with unknown reason
 (bsc#1180262).

usb: dwc2: Do not update data length if it is 0 on inbound transfers
 ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs", rpm: "kernel-docs~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build", rpm: "kernel-obs-build~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build-debugsource", rpm: "kernel-obs-build-debugsource~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-zfcpdump-debuginfo", rpm: "kernel-zfcpdump-debuginfo~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-zfcpdump-debugsource", rpm: "kernel-zfcpdump-debugsource~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "reiserfs-kmp-default", rpm: "reiserfs-kmp-default~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "reiserfs-kmp-default-debuginfo", rpm: "reiserfs-kmp-default-debuginfo~4.12.14~197.86.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

