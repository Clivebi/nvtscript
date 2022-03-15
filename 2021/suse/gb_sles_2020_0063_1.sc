if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0063.1" );
	script_cve_id( "CVE-2019-16775", "CVE-2019-16776", "CVE-2019-16777" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:11 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-07 16:49:00 +0000 (Wed, 07 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0063-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0063-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200063-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs10' package(s) announced via the SUSE-SU-2020:0063-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs10 to version 10.18.0 fixes the following issues:

Security issues fixed:
CVE-2019-16777, CVE-2019-16776, CVE-2019-16775: Updated npm to 6.13.4,
 fixing an arbitrary path overwrite and access via 'bin' field
 (bsc#1159352).

Added support for chacha20-poly1305 for Authenticated encryption (AEAD).

Non-security issues fixed:
Fix wrong path in gypi files (bsc#1159812)" );
	script_tag( name: "affected", value: "'nodejs10' package(s) on SUSE Linux Enterprise Module for Web Scripting 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs10", rpm: "nodejs10~10.18.0~1.15.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debuginfo", rpm: "nodejs10-debuginfo~10.18.0~1.15.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debugsource", rpm: "nodejs10-debugsource~10.18.0~1.15.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-devel", rpm: "nodejs10-devel~10.18.0~1.15.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-docs", rpm: "nodejs10-docs~10.18.0~1.15.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm10", rpm: "npm10~10.18.0~1.15.1", rls: "SLES12.0" ) )){
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

