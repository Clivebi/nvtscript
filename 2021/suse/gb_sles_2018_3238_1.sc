if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3238.1" );
	script_cve_id( "CVE-2018-14633", "CVE-2018-14634", "CVE-2018-17182" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 15:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3238-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3238-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183238-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 36 for SLE 12)' package(s) announced via the SUSE-SU-2018:3238-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 3.12.61-52_136 fixes several issues.

The following security issues were fixed:
CVE-2018-17182: The vmacache_flush_all function in mm/vmacache.c
 mishandled sequence number overflows. An attacker can trigger a
 use-after-free (and possibly gain privileges) via certain thread
 creation, map, unmap, invalidation, and dereference operations
 (bsc#1110233).

CVE-2018-14634: An unprivileged local user with access to SUID (or
 otherwise privileged) binary could use this flaw to escalate their
 privileges on the system. Kernel versions 2.6.x, 3.10.x and 4.14.x are
 believed to be vulnerable (bsc#1108963).

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
 unlikely. (bsc#1107832)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 36 for SLE 12)' package(s) on SUSE Linux Enterprise Server 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_101-default", rpm: "kgraft-patch-3_12_61-52_101-default~10~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_101-xen", rpm: "kgraft-patch-3_12_61-52_101-xen~10~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_106-default", rpm: "kgraft-patch-3_12_61-52_106-default~10~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_106-xen", rpm: "kgraft-patch-3_12_61-52_106-xen~10~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_111-default", rpm: "kgraft-patch-3_12_61-52_111-default~9~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_111-xen", rpm: "kgraft-patch-3_12_61-52_111-xen~9~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_119-default", rpm: "kgraft-patch-3_12_61-52_119-default~9~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_119-xen", rpm: "kgraft-patch-3_12_61-52_119-xen~9~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_122-default", rpm: "kgraft-patch-3_12_61-52_122-default~9~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_122-xen", rpm: "kgraft-patch-3_12_61-52_122-xen~9~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_125-default", rpm: "kgraft-patch-3_12_61-52_125-default~8~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_125-xen", rpm: "kgraft-patch-3_12_61-52_125-xen~8~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_128-default", rpm: "kgraft-patch-3_12_61-52_128-default~6~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_128-xen", rpm: "kgraft-patch-3_12_61-52_128-xen~6~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_133-default", rpm: "kgraft-patch-3_12_61-52_133-default~5~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_133-xen", rpm: "kgraft-patch-3_12_61-52_133-xen~5~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_136-default", rpm: "kgraft-patch-3_12_61-52_136-default~5~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_136-xen", rpm: "kgraft-patch-3_12_61-52_136-xen~5~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_141-default", rpm: "kgraft-patch-3_12_61-52_141-default~4~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_61-52_141-xen", rpm: "kgraft-patch-3_12_61-52_141-xen~4~2.1", rls: "SLES12.0" ) )){
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

