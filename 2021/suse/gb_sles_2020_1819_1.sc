if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1819.1" );
	script_cve_id( "CVE-2019-18934", "CVE-2020-12662", "CVE-2020-12663" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-17 21:00:00 +0000 (Wed, 17 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1819-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1819-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201819-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'unbound' package(s) announced via the SUSE-SU-2020:1819-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for unbound fixes the following issues:

CVE-2020-12662: Fixed an issue where unbound could have been tricked
 into amplifying an incoming query into a large number of queries
 directed to a target (bsc#1171889).

CVE-2020-12663: Fixed an issue where malformed answers from upstream
 name servers could have been used to make unbound unresponsive
 (bsc#1171889).

CVE-2019-18934: Fixed a vulnerability in the IPSec module which could
 have allowed code execution after receiving a special crafted answer
 (bsc#1157268)." );
	script_tag( name: "affected", value: "'unbound' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libunbound2", rpm: "libunbound2~1.6.8~3.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libunbound2-debuginfo", rpm: "libunbound2-debuginfo~1.6.8~3.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-anchor", rpm: "unbound-anchor~1.6.8~3.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-anchor-debuginfo", rpm: "unbound-anchor-debuginfo~1.6.8~3.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-debuginfo", rpm: "unbound-debuginfo~1.6.8~3.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-debugsource", rpm: "unbound-debugsource~1.6.8~3.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-devel", rpm: "unbound-devel~1.6.8~3.6.1", rls: "SLES15.0" ) )){
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

