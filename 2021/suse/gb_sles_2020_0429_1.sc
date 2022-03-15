if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0429.1" );
	script_cve_id( "CVE-2019-15604", "CVE-2019-15605", "CVE-2019-15606", "CVE-2019-16775", "CVE-2019-16776", "CVE-2019-16777" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:08 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0429-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0429-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200429-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs12' package(s) announced via the SUSE-SU-2020:0429-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs12 fixes the following issues:

nodejs12 was updated to version 12.15.0.

Security issues fixed:
CVE-2019-15604: Fixed a remotely triggerable assertion in the TLS server
 via a crafted certificate string (CVE-2019-15604, bsc#1163104).

CVE-2019-15605: Fixed an HTTP request smuggling vulnerability via
 malformed Transfer-Encoding header (CVE-2019-15605, bsc#1163102).

CVE-2019-15606: Fixed the white space sanitation of HTTP headers
 (CVE-2019-15606, bsc#1163103).

CVE-2019-16775: Fixed an arbitrary file write vulnerability
 (bsc#1159352).

CVE-2019-16776: Fixed an arbitrary file write vulnerability
 (bsc#1159352).

CVE-2019-16777: Fixed an arbitrary file write vulnerability
 (bsc#1159352)." );
	script_tag( name: "affected", value: "'nodejs12' package(s) on SUSE Linux Enterprise Module for Web Scripting 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs12", rpm: "nodejs12~12.15.0~1.6.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debuginfo", rpm: "nodejs12-debuginfo~12.15.0~1.6.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debugsource", rpm: "nodejs12-debugsource~12.15.0~1.6.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-devel", rpm: "nodejs12-devel~12.15.0~1.6.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-docs", rpm: "nodejs12-docs~12.15.0~1.6.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm12", rpm: "npm12~12.15.0~1.6.1", rls: "SLES12.0" ) )){
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

