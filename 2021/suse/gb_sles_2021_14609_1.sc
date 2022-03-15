if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.14609.1" );
	script_cve_id( "CVE-2020-26976", "CVE-2021-23953", "CVE-2021-23954", "CVE-2021-23960", "CVE-2021-23964" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:45 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-03 20:58:00 +0000 (Wed, 03 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:14609-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:14609-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-202114609-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2021:14609-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaFirefox fixes the following issues:

Firefox Extended Support Release 78.7.0 ESR (MFSA 2021-04, bsc#1181414)
 * CVE-2021-23953: Fixed a Cross-origin information leakage via
 redirected PDF requests
 * CVE-2021-23954: Fixed a type confusion when using logical assignment
 operators in JavaScript switch statements
 * CVE-2020-26976: Fixed an issue where HTTPS pages could have been
 intercepted by a registered service worker when they should not have
 been
 * CVE-2021-23960: Fixed a use-after-poison for incorrectly redeclared
 JavaScript variables during GC
 * CVE-2021-23964: Fixed Memory safety bugs" );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~78.7.0~78.114.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-common", rpm: "MozillaFirefox-translations-common~78.7.0~78.114.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-other", rpm: "MozillaFirefox-translations-other~78.7.0~78.114.1", rls: "SLES11.0SP4" ) )){
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
