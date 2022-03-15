if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1536.1" );
	script_cve_id( "CVE-2018-7191", "CVE-2019-10124", "CVE-2019-11085", "CVE-2019-11477", "CVE-2019-11479", "CVE-2019-11486", "CVE-2019-11487", "CVE-2019-11815", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-12382", "CVE-2019-3846", "CVE-2019-5489" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 14:37:00 +0000 (Thu, 15 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1536-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1536-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191536-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1536-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP4 kernel was updated to 4.12.14 to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-11477: A sequence of SACKs may have been crafted such that one
 can trigger an integer overflow, leading to a kernel panic.

CVE-2019-11479: An attacker could force the Linux kernel to segment its
 responses into multiple TCP segments. This would drastically increased
 the bandwidth required to deliver the same amount of data. Further, it
 would consume additional resources such as CPU and NIC processing power.

CVE-2019-3846: A flaw that allowed an attacker to corrupt memory and
 possibly escalate privileges was found in the mwifiex kernel module
 while connecting to a malicious wireless network. (bnc#1136424)

CVE-2019-12382: An issue was discovered in drm_load_edid_firmware in
 drivers/gpu/drm/drm_edid_load.c in the Linux kernel There was an
 unchecked kstrdup of fwstr, which might have allowed an attacker to
 cause a denial of service (NULL pointer dereference and system crash).
 (bnc#1136586)

CVE-2019-11487: The Linux kernel allowed page reference count overflow,
 with resultant use-after-free issues, if about 140 GiB of RAM existed.
 It could have occured with FUSE requests. (bnc#1133190)

CVE-2019-5489: The mincore() implementation in mm/mincore.c in the Linux
 kernel allowed local attackers to observe page cache access patterns of
 other processes on the same system, potentially allowing sniffing of
 secret information. (Fixing this affects the output of the fincore
 program.) Limited remote exploitation may have been possible, as
 demonstrated by latency differences in accessing public files from an
 Apache HTTP Server. (bnc#1120843)

CVE-2019-11833: fs/ext4/extents.c in the Linux kernel did not zero out
 the unused memory region in the extent tree block, which might have
 allowed local users to obtain sensitive information by reading
 uninitialized data in the filesystem. (bnc#1135281)

CVE-2018-7191: In the tun subsystem in the Linux kernel,
 dev_get_valid_name was not called before register_netdevice. This
 allowed local users to cause a denial of service (NULL pointer
 dereference and panic) via an ioctl(TUNSETIFF) call with a dev name
 containing a / character. (bnc#1135603)

CVE-2019-11085: Insufficient input validation in Kernel Mode Driver in
 i915 Graphics for Linux may have allowed an authenticated user to
 potentially enable escalation of privilege via local access.
 (bnc#1135278)

CVE-2019-11815: An issue was discovered in rds_tcp_kill_sock in
 net/rds/tcp.c in the Linux kernel There was a race condition leading to
 a use-after-free, related to net namespace cleanup. (bnc#1134537)

CVE-2019-11884: The do_hidp_sock_ioctl function in
 net/bluetooth/hidp/sock.c in the Linux kernel allowed a local user to
 obtain potentially sensitive information from kernel stack memory via a
 hidPCONNADD command, ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~6.15.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~6.15.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~6.15.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~6.15.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.12.14~6.15.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~6.15.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~6.15.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~6.15.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~6.15.2", rls: "SLES12.0SP4" ) )){
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

