if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0742.1" );
	script_cve_id( "CVE-2021-3348" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-31 00:15:00 +0000 (Wed, 31 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0742-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0742-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210742-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0742-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bug was fixed:

CVE-2021-3348: Fixed a use-after-free read in nbd_queue_rq (bsc#1181504).

The following non-security bugs were fixed:

ACPI: configfs: add missing check after
 configfs_register_default_group() (git-fixes).

ACPI: property: Fix fwnode string properties matching (git-fixes).

ACPI: property: Satisfy kernel doc validator (part 1) (git-fixes).

ALSA: usb-audio: Fix PCM buffer allocation in non-vmalloc mode
 (git-fixes).

arm64: Update config file. Set CONFIG_WATCHDOG_SYSFS to true
 (bsc#1182560)

ASoC: cs42l56: fix up error handling in probe (git-fixes).

ath9k: fix data bus crash when setting nf_override via debugfs
 (git-fixes).

block: fix use-after-free in disk_part_iter_next (bsc#1182610).

Bluetooth: btqcomsmd: Fix a resource leak in error handling paths in the
 probe function (git-fixes).

Bluetooth: drop HCI device reference before return (git-fixes).

Bluetooth: Fix initializing response id after clearing struct
 (git-fixes).

Bluetooth: Put HCI device if inquiry procedure interrupts (git-fixes).

bonding: Fix reference count leak in bond_sysfs_slave_add (git-fixes).

bonding: wait for sysfs kobject destruction before freeing struct slave
 (git-fixes).

BTRFS: Cleanup try_flush_qgroup (bsc#1182047).

BTRFS: correctly calculate item size used when item key collision
 happens (bsc#1181996).

BTRFS: correctly validate compression type (bsc#1182269).

BTRFS: delete the ordered isize update code (bsc#1181998).

BTRFS: Do not flush from btrfs_delayed_inode_reserve_metadata
 (bsc#1182047).

BTRFS: do not set path->leave_spinning for truncate (bsc#1181998).

BTRFS: factor out extent dropping code from hole punch handler
 (bsc#1182038).

BTRFS: fix cloning range with a hole when using the NO_HOLES feature
 (bsc#1182038).

BTRFS: fix data bytes_may_use underflow with fallocate due to failed
 quota reserve (bsc#1182130)

BTRFS: fix ENOSPC errors, leading to transaction aborts, when cloning
 extents (bsc#1182038).

BTRFS: fix hole extent items with a zero size after range cloning
 (bsc#1182038).

BTRFS: fix lost i_size update after cloning inline extent (bsc#1181998).

BTRFS: fix mount failure caused by race with umount (bsc#1182248).

BTRFS: Fix race between extent freeing/allocation when using bitmaps
 (bsc#1181574).

BTRFS: fix unexpected cow in run_delalloc_nocow (bsc#1181987).

BTRFS: fix unexpected failure of nocow buffered writes after
 snapshotting when low on space (bsc#1181987).

BTRFS: Free correct amount of space in
 btrfs_delayed_inode_reserve_metadata (bsc#1182047).

BTRFS: incremental send, fix file corruption when no-holes feature is
 enabled (bsc#1182184).

BTRFS: Introduce extent_io_tree::owner to distinguish different io_trees
 (bsc#1181998).

BTRFS: introduce per-inode file extent tree (bsc#1181998).

BTRFS: prepare for ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP5, SUSE Linux Enterprise Live Patching 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5." );
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~122.63.1", rls: "SLES12.0SP5" ) )){
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

