if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.13924.1" );
	script_cve_id( "CVE-2015-2775", "CVE-2016-6893", "CVE-2018-0618", "CVE-2018-13796", "CVE-2018-5950" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:32 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:13924-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:13924-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-201913924-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mailman' package(s) announced via the SUSE-SU-2019:13924-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mailman fixes the following issues:
Fixed a XSS vulnerability and information leak in user options CGI,
 which could be used to execute arbitrary scripts in the user's browser
 via specially encoded URLs (bsc#1077358 CVE-2018-5950)

Fixed a directory traversal vulnerability in MTA transports when using
 the recommended Mailman Transport for Exim (bsc#925502 CVE-2015-2775)

Fixed a XSS vulnerability, which allowed malicious listowners to inject
 scripts into the listinfo pages (bsc#1099510 CVE-2018-0618)

Fixed arbitrary text injection vulnerability in several mailman CGIs
 (CVE-2018-13796 bsc#1101288)

Fixed a CSRF vulnerability on the user options page (CVE-2016-6893
 bsc#995352)" );
	script_tag( name: "affected", value: "'mailman' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "mailman", rpm: "mailman~2.1.15~9.6.6.1", rls: "SLES11.0SP3" ) )){
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "mailman", rpm: "mailman~2.1.15~9.6.6.1", rls: "SLES11.0SP4" ) )){
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
