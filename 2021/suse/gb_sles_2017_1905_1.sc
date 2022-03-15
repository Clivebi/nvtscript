if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1905.1" );
	script_cve_id( "CVE-2017-1000364" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-18 10:29:00 +0000 (Thu, 18 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1905-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1905-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171905-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel Live Patch 16 for SLE 12' package(s) announced via the SUSE-SU-2017:1905-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 3.12.60-52_57 fixes several issues.
The following security bugs were fixed:
- CVE-2017-1000364: An issue was discovered in the size of the stack guard
 page on Linux, specifically a 4k stack guard page is not sufficiently
 large and can be 'jumped' over (the stack guard page is bypassed)
 (bsc#1039496)." );
	script_tag( name: "affected", value: "'Linux Kernel Live Patch 16 for SLE 12' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_60-52_57-default", rpm: "kgraft-patch-3_12_60-52_57-default~7~3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_60-52_57-xen", rpm: "kgraft-patch-3_12_60-52_57-xen~7~3.1", rls: "SLES12.0" ) )){
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

