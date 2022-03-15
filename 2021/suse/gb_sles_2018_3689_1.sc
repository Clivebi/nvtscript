if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3689.1" );
	script_cve_id( "CVE-2018-10940", "CVE-2018-14633", "CVE-2018-16658", "CVE-2018-18281", "CVE-2018-18386", "CVE-2018-18690", "CVE-2018-18710", "CVE-2018-9516" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3689-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3689-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183689-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:3689-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.162 to receive various security and bugfixes.

The following security bugs were fixed:
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

CVE-2018-18281: The mremap() syscall performs TLB flushes after dropping
 pagetable locks. If a syscall such as ftruncate() removes entries from
 the pagetables of a task that is in the middle of mremap(), a stale TLB
 entry can remain for a short time that permits access to a physical page
 after it has been released back to the page allocator and reused.
 (bnc#1113769).

CVE-2018-18386: drivers/tty/n_tty.c allowed local attackers (who are
 able to access pseudo terminals) to hang/block further usage of any
 pseudo terminal devices due to an EXTPROC versus ICANON confusion in
 TIOCINQ (bnc#1094825).

CVE-2018-18690: A local attacker able to set attributes on an xfs
 filesystem could make this filesystem non-operational until the next
 mount by triggering an unchecked error condition during an xfs attribute
 change, because xfs_attr_shortform_addname in fs/xfs/libxfs/xfs_attr.c
 mishandled ATTR_REPLACE operations with conversion of an attr from short
 to long form (bnc#1105025).

CVE-2018-18710: An issue was discovered in the Linux kernel An
 information leak in cdrom_ioctl_select_disc in drivers/cdrom/cdrom.c
 could be used by local attackers to read kernel memory because a cast
 from unsigned long to int interferes with bounds checking. This is
 similar to CVE-2018-10940 and CVE-2018-16658 (bnc#1113751).

CVE-2018-9516: A lack of certain checks in the hid_debug_events_read()
 function in the drivers/hid/hid-debug.c file might have resulted in
 receiving userspace buffer overflow and an out-of-bounds write or to the
 infinite loop. (bnc#1108498).

The following non-security bugs were fixed:
6lowpan: iphc: reset mac_header after decompress to fix panic
 (bnc#1012382).

alsa: bebob: use address returned by kmalloc() instead of kernel stack
 for streaming DMA mapping (bnc#1012382).

alsa: emu10k1: fix possible info leak to userspace on
 SNDRV_EMU10K1_IOCTL_INFO (bnc#1012382).

alsa: hda: Add AZX_DCAPS_PM_RUNTIME for AMD Raven Ridge (bnc#1012382).

alsa: hda - Fix ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.162~94.69.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules", rpm: "lttng-modules~2.7.1~8.6.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules-debugsource", rpm: "lttng-modules-debugsource~2.7.1~8.6.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules-kmp-default", rpm: "lttng-modules-kmp-default~2.7.1_k4.4.162_94.69~8.6.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules-kmp-default-debuginfo", rpm: "lttng-modules-kmp-default-debuginfo~2.7.1_k4.4.162_94.69~8.6.1", rls: "SLES12.0SP3" ) )){
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

