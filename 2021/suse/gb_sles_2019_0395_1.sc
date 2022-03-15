if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0395.1" );
	script_cve_id( "CVE-2018-0734", "CVE-2018-12116", "CVE-2018-12120", "CVE-2018-12121", "CVE-2018-12122", "CVE-2018-12123", "CVE-2018-5407" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0395-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0395-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190395-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs6' package(s) announced via the SUSE-SU-2019:0395-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs6 to version 6.16.0 fixes the following issues:

Security issues fixed:
CVE-2018-0734: Fixed a timing vulnerability in the DSA signature
 generation (bsc#1113652)

CVE-2018-5407: Fixed a hyperthread port content side channel attack (aka
 'PortSmash') (bsc#1113534)

CVE-2018-12120: Fixed that the debugger listens on any interface by
 default (bsc#1117625)

CVE-2018-12121: Fixed a denial of Service with large HTTP headers
 (bsc#1117626)

CVE-2018-12122: Fixed the 'Slowloris' HTTP Denial of Service
 (bsc#1117627)

CVE-2018-12116: Fixed HTTP request splitting (bsc#1117630)

CVE-2018-12123: Fixed hostname spoofing in URL parser for javascript
 protocol (bsc#1117629)" );
	script_tag( name: "affected", value: "'nodejs6' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Module for Web Scripting 12, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud Crowbar 8." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs6", rpm: "nodejs6~6.16.0~11.21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs6-debuginfo", rpm: "nodejs6-debuginfo~6.16.0~11.21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs6-debugsource", rpm: "nodejs6-debugsource~6.16.0~11.21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs6-devel", rpm: "nodejs6-devel~6.16.0~11.21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs6-docs", rpm: "nodejs6-docs~6.16.0~11.21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm6", rpm: "npm6~6.16.0~11.21.1", rls: "SLES12.0" ) )){
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

