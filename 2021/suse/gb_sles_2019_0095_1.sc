if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0095.1" );
	script_cve_id( "CVE-2018-10940", "CVE-2018-14613", "CVE-2018-14617", "CVE-2018-14633", "CVE-2018-16276", "CVE-2018-16597", "CVE-2018-16658", "CVE-2018-17182", "CVE-2018-18281", "CVE-2018-18386", "CVE-2018-18690", "CVE-2018-18710", "CVE-2018-7480", "CVE-2018-7757", "CVE-2018-9516" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 17:06:00 +0000 (Fri, 08 Mar 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0095-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0095-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190095-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0095-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP3 Azure kernel was updated to 4.4.162 to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-18281: The mremap() syscall performs TLB flushes after dropping
 pagetable locks. If a syscall such as ftruncate() removes entries from
 the pagetables of a task that is in the middle of mremap(), a stale TLB
 entry can remain for a short time that permits access to a physical page
 after it has been released back to the page allocator and reused.
 (bnc#1113769).

CVE-2018-18710: An information leak in cdrom_ioctl_select_disc in
 drivers/cdrom/cdrom.c could be used by local attackers to read kernel
 memory because a cast from unsigned long to int interferes with bounds
 checking. This is similar to CVE-2018-10940 and CVE-2018-16658
 (bnc#1113751).

CVE-2018-18690: A local attacker able to set attributes on an xfs
 filesystem could make this filesystem non-operational until the next
 mount by triggering an unchecked error condition during an xfs attribute
 change, because xfs_attr_shortform_addname in fs/xfs/libxfs/xfs_attr.c
 mishandled ATTR_REPLACE operations with conversion of an attr from short
 to long form (bnc#1105025).

CVE-2018-18386: drivers/tty/n_tty.c allowed local attackers (who are
 able to access pseudo terminals) to hang/block further usage of any
 pseudo terminal devices due to an EXTPROC versus ICANON confusion in
 TIOCINQ (bnc#1094825).

CVE-2018-9516: In hid_debug_events_read of drivers/hid/hid-debug.c,
 there is a possible out of bounds write due to a missing bounds check.
 This could lead to local escalation of privilege with System execution
 privileges needed. User interaction is not needed for exploitation.
 (bnc#1108498).

CVE-2018-14633: A security flaw was found in the
 chap_server_compute_md5() function in the ISCSI target code in a way an
 authentication request from an ISCSI initiator is processed. An
 unauthenticated remote attacker can cause a stack buffer overflow and
 smash up to 17 bytes of the stack. The attack requires the iSCSI target
 to be enabled on the victim host. Depending on how the target's code was
 built (i.e. depending on a compiler, compile flags and hardware
 architecture) an attack may lead to a system crash and thus to a
 denial-of-service or possibly to a non-authorized access to data
 exported by an iSCSI target. Due to the nature of the flaw, privilege
 escalation cannot be fully ruled out, although we believe it is highly
 unlikely. (bnc#1107829).

CVE-2018-17182: The vmacache_flush_all function in mm/vmacache.c
 mishandled sequence number overflows. An attacker can trigger a
 use-after-free (and possibly gain privileges) via certain thread
 creation, map, unmap, invalidation, and dereference operations
 (bnc#1108399).

CVE-2018-16597: Incorrect access checking in overlayfs mounts could be
 used by local attackers to modify or truncate files in the ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.4.162~4.19.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.4.162~4.19.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.4.162~4.19.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.4.162~4.19.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.4.162~4.19.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.4.162~4.19.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.4.162~4.19.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.4.162~4.19.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.4.162~4.19.1", rls: "SLES12.0SP3" ) )){
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

