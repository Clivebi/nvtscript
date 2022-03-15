if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1606.1" );
	script_cve_id( "CVE-2020-11080", "CVE-2020-7598", "CVE-2020-8172", "CVE-2020-8174" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:01 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1606-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1606-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201606-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs12' package(s) announced via the SUSE-SU-2020:1606-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs12 fixes the following issues:

nodejs12 was updated to version 12.18.0

CVE-2020-8174: Fixed multiple memory corruption in
 napi_get_value_string_*() (bsc#1172443).

CVE-2020-8172: Fixed am issue where TLS session reuse could have led to
 host certificate verification bypass (bsc#1172441).

CVE-2020-11080: Fixed a potential denial of service when receiving
 unreasonably large HTTP/2 SETTINGS frames (bsc#1172442).

npm was updated to 6.13.6

CVE-2020-7598: Fixed an issue which could have tricked minimist into
 adding or modifying properties of Object.prototype (bsc#1166916)." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs12", rpm: "nodejs12~12.18.0~1.14.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debuginfo", rpm: "nodejs12-debuginfo~12.18.0~1.14.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debugsource", rpm: "nodejs12-debugsource~12.18.0~1.14.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-devel", rpm: "nodejs12-devel~12.18.0~1.14.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-docs", rpm: "nodejs12-docs~12.18.0~1.14.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm12", rpm: "npm12~12.18.0~1.14.1", rls: "SLES12.0" ) )){
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

