if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1075.1" );
	script_cve_id( "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-09 09:15:00 +0000 (Fri, 09 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1075-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1075-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211075-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 5 for SLE 12 SP5)' package(s) announced via the SUSE-SU-2021:1075-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 4.12.14-122_222 fixes several issues.

The following security issues were fixed:

CVE-2021-27365: Fixed an issue where data structures did not have
 appropriate length constraints or checks, and could exceed the PAGE_SIZE
 value (bsc#1183491).

CVE-2021-27363: Fixed a kernel pointer leak which could have been used
 to determine the address of the iscsi_transport structure (bsc#1183120).

CVE-2021-27364: Fixed an issue where an unprivileged user could craft
 Netlink messages (bsc#1182717)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 5 for SLE 12 SP5)' package(s) on SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise Live Patching 12-SP5, SUSE Linux Enterprise Module for Live Patching 15, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_116-default", rpm: "kgraft-patch-4_4_180-94_116-default~9~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_116-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_116-default-debuginfo~9~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_121-default", rpm: "kgraft-patch-4_4_180-94_121-default~8~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_121-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_121-default-debuginfo~8~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_124-default", rpm: "kgraft-patch-4_4_180-94_124-default~8~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_124-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_124-default-debuginfo~8~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_127-default", rpm: "kgraft-patch-4_4_180-94_127-default~8~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_127-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_127-default-debuginfo~8~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_130-default", rpm: "kgraft-patch-4_4_180-94_130-default~7~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_130-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_130-default-debuginfo~7~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_135-default", rpm: "kgraft-patch-4_4_180-94_135-default~5~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_135-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_135-default-debuginfo~5~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_138-default", rpm: "kgraft-patch-4_4_180-94_138-default~3~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_138-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_138-default-debuginfo~3~2.2", rls: "SLES12.0SP3" ) )){
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

