if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0870.1" );
	script_cve_id( "CVE-2020-27786", "CVE-2020-28374", "CVE-2021-3347" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-15 22:04:00 +0000 (Mon, 15 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0870-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0870-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210870-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 36 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2021:0870-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 4.4.121-92_138 fixes several issues.

The following security issues were fixed:

CVE-2021-3347: Fixed a use-after-free in the PI futexes during fault
 handling, allowing local users to execute code in the kernel
 (bsc#1181553).

CVE-2020-27786: Fixed a potential user after free which could have led
 to memory corruption or privilege escalation (bsc#1179616).

CVE-2020-28374: Fixed insufficient identifier checking in the LIO SCSI
 target code which could have been used by remote attackers to read or
 write files via directory traversal in an XCOPY request (bsc#1178684)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 36 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_129-default", rpm: "kgraft-patch-4_4_121-92_129-default~9~2.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_135-default", rpm: "kgraft-patch-4_4_121-92_135-default~7~2.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_138-default", rpm: "kgraft-patch-4_4_121-92_138-default~7~2.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_141-default", rpm: "kgraft-patch-4_4_121-92_141-default~6~2.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_146-default", rpm: "kgraft-patch-4_4_121-92_146-default~4~2.2", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_116-default", rpm: "kgraft-patch-4_4_180-94_116-default~8~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_116-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_116-default-debuginfo~8~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_121-default", rpm: "kgraft-patch-4_4_180-94_121-default~7~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_121-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_121-default-debuginfo~7~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_124-default", rpm: "kgraft-patch-4_4_180-94_124-default~7~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_124-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_124-default-debuginfo~7~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_127-default", rpm: "kgraft-patch-4_4_180-94_127-default~7~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_127-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_127-default-debuginfo~7~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_130-default", rpm: "kgraft-patch-4_4_180-94_130-default~6~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_130-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_130-default-debuginfo~6~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_135-default", rpm: "kgraft-patch-4_4_180-94_135-default~4~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_135-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_135-default-debuginfo~4~2.2", rls: "SLES12.0SP3" ) )){
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

