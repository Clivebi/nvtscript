if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0439.1" );
	script_cve_id( "CVE-2018-10940", "CVE-2018-16658", "CVE-2018-16862", "CVE-2018-16884", "CVE-2018-18281", "CVE-2018-18386", "CVE-2018-18690", "CVE-2018-18710", "CVE-2018-19824", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-9516", "CVE-2018-9568", "CVE-2019-3459", "CVE-2019-3460" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0439-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0439-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190439-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0439-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-19985: The function hso_probe read if_num from the USB device
 (as an u8) and used it without a length check to index an array,
 resulting in an OOB memory read in hso_probe or hso_get_config_data that
 could be used by local attackers (bnc#1120743).

CVE-2018-16884: NFS41+ shares mounted in different network namespaces at
 the same time can make bc_svc_process() use wrong back-channel IDs and
 cause a use-after-free vulnerability. Thus a malicious container user
 can cause a host kernel memory corruption and a system panic. Due to the
 nature of the flaw, privilege escalation cannot be fully ruled out
 (bnc#1119946).

CVE-2018-20169: The USB subsystem mishandled size checks during the
 reading of an extra descriptor, related to __usb_get_extra_descriptor in
 drivers/usb/core/usb.c (bnc#1119714).

CVE-2018-9568: In sk_clone_lock of sock.c, there is a possible memory
 corruption due to type confusion. This could lead to local escalation of
 privilege with no additional execution privileges needed. User
 interaction is not needed for exploitation. (bnc#1118319).

CVE-2018-16862: A security flaw was found in a way that the cleancache
 subsystem clears an inode after the final file truncation (removal). The
 new file created with the same inode may contain leftover pages from
 cleancache and the old file data instead of the new one (bnc#1117186).

CVE-2018-19824: A local user could exploit a use-after-free in the ALSA
 driver by supplying a malicious USB Sound device (with zero interfaces)
 that is mishandled in usb_audio_probe in sound/usb/card.c (bnc#1118152).

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
 ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE Enterprise Storage 4, SUSE Linux Enterprise High Availability 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE OpenStack Cloud 7." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.121~92.101.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_101-default", rpm: "kgraft-patch-4_4_121-92_101-default~1~3.3.1", rls: "SLES12.0SP2" ) )){
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

