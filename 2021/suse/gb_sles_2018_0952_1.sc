if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0952.1" );
	script_cve_id( "CVE-2018-7158", "CVE-2018-7159" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:46 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-13 16:51:00 +0000 (Thu, 13 Feb 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0952-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0952-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180952-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs4' package(s) announced via the SUSE-SU-2018:0952-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs4 fixes the following issues:
- Fix some node-gyp permissions
- New upstream maintenance 4.9.1:
 * Security fixes:
 + CVE-2018-7158: Fix for 'path' module regular expression denial of
 service (bsc#1087459)
 + CVE-2018-7159: Reject spaces in HTTP Content-Length header values
 (bsc#1087453)
 * Upgrade to OpenSSL 1.0.2o
 * deps: reject interior blanks in Content-Length
 * deps: upgrade http-parser to v2.8.0
- remove any old manpage files in %pre from before update-alternatives
 were used to manage symlinks to these manpages.
- Add Recommends and BuildRequire on python2 for npm. node-gyp requires
 this old version of python for now. This is only needed for binary
 modules.
- even on recent codestreams there is no binutils gold on s390
 only on s390x
- Enable CI tests in %check target" );
	script_tag( name: "affected", value: "'nodejs4' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Module for Web Scripting 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs4", rpm: "nodejs4~4.9.1~15.11.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-debuginfo", rpm: "nodejs4-debuginfo~4.9.1~15.11.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-debugsource", rpm: "nodejs4-debugsource~4.9.1~15.11.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-devel", rpm: "nodejs4-devel~4.9.1~15.11.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-docs", rpm: "nodejs4-docs~4.9.1~15.11.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm4", rpm: "npm4~4.9.1~15.11.1", rls: "SLES12.0" ) )){
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

