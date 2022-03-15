if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2981.1" );
	script_cve_id( "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-25212", "CVE-2020-25645" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-08 16:15:00 +0000 (Thu, 08 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2981-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2981-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202981-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2981-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-12351: Fixed a type confusion while processing AMP packets aka
 'BleedingTooth' aka 'BadKarma' (bsc#1177724).

CVE-2020-12352: Fixed an information leak when processing certain AMP
 packets aka 'BleedingTooth' aka 'BadChoice' (bsc#1177725).

CVE-2020-25645: Fixed an issue which traffic between two Geneve
 endpoints may be unencrypted when IPsec is configured to encrypt traffic
 for the specific UDP port used by the GENEVE tunnel allowing anyone
 between the two endpoints to read the traffic unencrypted (bsc#1177511).

CVE-2020-25212: Fixed a TOCTOU mismatch in the NFS client code
 (bsc#1176381).

The following non-security bugs were fixed:

btrfs: check the right error variable in btrfs_del_dir_entries_in_log
 (bsc#1177687).

btrfs: do not set the full sync flag on the inode during page release
 (bsc#1177687).

btrfs: fix incorrect updating of log root tree (bsc#1177687).

btrfs: fix race between page release and a fast fsync (bsc#1177687).

btrfs: only commit delayed items at fsync if we are logging a directory
 (bsc#1177687).

btrfs: only commit the delayed inode when doing a full fsync
 (bsc#1177687).

btrfs: reduce contention on log trees when logging checksums
 (bsc#1177687).

btrfs: release old extent maps during page release (bsc#1177687).

btrfs: remove no longer needed use of log_writers for the log root tree
 (bsc#1177687).

btrfs: stop incremening log_batch for the log root tree when syncing log
 (bsc#1177687).

drm/amdgpu: prevent double kfree ttm->sg (git-fixes).

drm/nouveau/mem: guard against NULL pointer access in mem_del
 (git-fixes).

drm/sun4i: mixer: Extend regmap max_register (git-fixes).

ext4: fix dir_nlink behaviour (bsc#1177359).

i2c: meson: fix clock setting overwrite (git-fixes).

include/linux/swapops.h: correct guards for non_swap_entry() (git-fixes
 (mm/swap)).

iommu/vt-d: Correctly calculate agaw in domain_init() (bsc#1176400).

leds: mt6323: move period calculation (git-fixes).

mac80211: do not allow bigger VHT MPDUs than the hardware supports
 (git-fixes).

macsec: avoid use-after-free in macsec_handle_frame() (git-fixes).

mfd: sm501: Fix leaks in probe() (git-fixes).

mmc: core: do not set limits.discard_granularity as 0 (git-fixes).

mm/huge_memory.c: use head to check huge zero page (git-fixes (mm/thp)).

mm: hugetlb: switch to css_tryget() in hugetlb_cgroup_charge_cgroup()
 (git-fixes (mm/hugetlb)).

mm/ksm.c: do not WARN if page is still mapped in remove_stable_node()
 (git-fixes (mm/hugetlb)).

mm: memcg: switch to css_tryget() in get_mem_cgroup_from_mm()
 (bsc#1177685).

mm/mempolicy.c: fix out of bounds write in mpol_parse_str() (git-fixes
 (mm/mempolicy)).

mm/mempolicy.c: use match_string() helper to simplify the code
 (git-fixes (mm/mempolicy)).

mm, numa: fix bad pmd by atomically ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~122.46.1", rls: "SLES12.0SP5" ) )){
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

