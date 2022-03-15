if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0688.1" );
	script_cve_id( "CVE-2014-1344", "CVE-2014-1384", "CVE-2014-1385", "CVE-2014-1386", "CVE-2014-1387", "CVE-2014-1388", "CVE-2014-1389", "CVE-2014-1390", "CVE-2015-2330" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0688-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0688-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150688-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkitgtk' package(s) announced via the SUSE-SU-2015:0688-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes the following security issues:

- Fix SSL connection issues with some websites after the POODLE
 vulnerability fix.
- Fix a crash when loading flash plugins.
- Fix build on GNU Hurd - Fix build on OS X.
- Fix documentation of webkit_print_operation_get_page_setup().
- Security fixes: CVE-2014-1344, CVE-2014-1384, CVE-2014-1385,
 CVE-2014-1386, CVE-2014-1387, CVE-2014-1388, CVE-2014-1389,
 CVE-2014-1390, CVE-2015-2330. (bnc#879607, bnc#871792)
- Pass autoreconf and enable libtool BuildRequires: Needed for above patch
 since it touches the buildsystem.
- Bugs fixed: boo#871792, boo#879607 and boo#879607." );
	script_tag( name: "affected", value: "'webkitgtk' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Workstation Extension 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-3_0-0", rpm: "libjavascriptcoregtk-3_0-0~2.4.8~16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-3_0-0-debuginfo", rpm: "libjavascriptcoregtk-3_0-0-debuginfo~2.4.8~16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkitgtk-3_0-0", rpm: "libwebkitgtk-3_0-0~2.4.8~16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkitgtk-3_0-0-debuginfo", rpm: "libwebkitgtk-3_0-0-debuginfo~2.4.8~16.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkitgtk3-lang", rpm: "libwebkitgtk3-lang~2.4.8~16.2", rls: "SLES12.0" ) )){
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

