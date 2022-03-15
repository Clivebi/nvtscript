if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2354.1" );
	script_cve_id( "CVE-2020-7774", "CVE-2021-22918", "CVE-2021-23362", "CVE-2021-27290" );
	script_tag( name: "creation_date", value: "2021-07-16 02:27:40 +0000 (Fri, 16 Jul 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-09 13:27:00 +0000 (Fri, 09 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2354-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2|SLES15\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2354-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212354-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs14' package(s) announced via the SUSE-SU-2021:2354-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs14 fixes the following issues:

Update nodejs14 to 14.17.2.

Including fixes for:

CVE-2021-22918: libuv upgrade - Out of bounds read (bsc#1187973)

CVE-2021-27290: ssri Regular Expression Denial of Service (bsc#1187976)

CVE-2021-23362: hosted-git-info Regular Expression Denial of Service
 (bsc#1187977)

CVE-2020-7774: y18n Prototype Pollution (bsc#1184450)" );
	script_tag( name: "affected", value: "'nodejs14' package(s) on SUSE Linux Enterprise Module for Web Scripting 15-SP2, SUSE Linux Enterprise Module for Web Scripting 15-SP3." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "nodejs14", rpm: "nodejs14~14.17.2~5.12.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs14-debuginfo", rpm: "nodejs14-debuginfo~14.17.2~5.12.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs14-debugsource", rpm: "nodejs14-debugsource~14.17.2~5.12.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs14-devel", rpm: "nodejs14-devel~14.17.2~5.12.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs14-docs", rpm: "nodejs14-docs~14.17.2~5.12.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm14", rpm: "npm14~14.17.2~5.12.1", rls: "SLES15.0SP2" ) )){
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "nodejs14", rpm: "nodejs14~14.17.2~5.12.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs14-debuginfo", rpm: "nodejs14-debuginfo~14.17.2~5.12.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs14-debugsource", rpm: "nodejs14-debugsource~14.17.2~5.12.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs14-devel", rpm: "nodejs14-devel~14.17.2~5.12.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs14-docs", rpm: "nodejs14-docs~14.17.2~5.12.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm14", rpm: "npm14~14.17.2~5.12.1", rls: "SLES15.0SP3" ) )){
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

