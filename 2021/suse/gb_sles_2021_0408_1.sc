if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0408.1" );
	script_cve_id( "CVE-2020-0465", "CVE-2020-0466", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0408-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0408-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210408-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 32 for SLE 12 SP3)' package(s) announced via the SUSE-SU-2021:0408-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 4.4.180-94_121 fixes several issues.

The following security issues were fixed:

CVE-2020-36158: Fixed a potential remote code execution in the Marvell
 mwifiex driver (bsc#1180562).

CVE-2020-0465: Fixed multiple missing bounds checks in hid-multitouch.c
 that could have led to local privilege escalation (bnc#1180030).

CVE-2020-0466: Fixed a use-after-free due to a logic error in
 do_epoll_ctl and ep_loop_check_proc of eventpoll.c (bnc#1180032.

CVE-2020-29569: Fixed a use after free due to a logic error
 (bsc#1180008).

CVE-2020-29660: Fixed a locking inconsistency in the tty subsystem that
 may have allowed a read-after-free attack against TIOCGSID (bsc#1179877).

CVE-2020-29661: Fixed a locking issue in the tty subsystem that allowed
 a use-after-free attack against TIOCSPGRP (bsc#1179877)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 32 for SLE 12 SP3)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_129-default", rpm: "kgraft-patch-4_4_121-92_129-default~8~2.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_135-default", rpm: "kgraft-patch-4_4_121-92_135-default~6~2.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_138-default", rpm: "kgraft-patch-4_4_121-92_138-default~6~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_141-default", rpm: "kgraft-patch-4_4_121-92_141-default~5~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_146-default", rpm: "kgraft-patch-4_4_121-92_146-default~3~2.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_116-default", rpm: "kgraft-patch-4_4_180-94_116-default~7~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_116-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_116-default-debuginfo~7~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_121-default", rpm: "kgraft-patch-4_4_180-94_121-default~6~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_121-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_121-default-debuginfo~6~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_124-default", rpm: "kgraft-patch-4_4_180-94_124-default~6~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_124-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_124-default-debuginfo~6~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_127-default", rpm: "kgraft-patch-4_4_180-94_127-default~6~2.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_127-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_127-default-debuginfo~6~2.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_130-default", rpm: "kgraft-patch-4_4_180-94_130-default~5~2.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_130-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_130-default-debuginfo~5~2.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_135-default", rpm: "kgraft-patch-4_4_180-94_135-default~3~2.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_135-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_135-default-debuginfo~3~2.1", rls: "SLES12.0SP3" ) )){
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

