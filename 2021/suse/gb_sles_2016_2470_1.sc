if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2470.1" );
	script_cve_id( "CVE-2016-2178", "CVE-2016-2183", "CVE-2016-5325", "CVE-2016-6304", "CVE-2016-6306", "CVE-2016-7052", "CVE-2016-7099" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-06 16:11:00 +0000 (Wed, 06 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2470-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2470-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162470-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs4' package(s) announced via the SUSE-SU-2016:2470-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update brings the new upstream nodejs LTS version 4.6.0, fixing bugs and security issues:
* Nodejs embedded openssl version update
 + upgrade to 1.0.2j (CVE-2016-6304, CVE-2016-2183, CVE-2016-2178,
 CVE-2016-6306, CVE-2016-7052)
 + remove support for dynamic 3rd party engine modules
* http: Properly validate for allowable characters in input user data.
 This introduces a new case where throw may occur when configuring HTTP
 responses, users should already be adopting try/catch here.
 (CVE-2016-5325, bsc#985201)
* tls: properly validate wildcard certificates (CVE-2016-7099, bsc#1001652)
* buffer: Zero-fill excess bytes in new Buffer objects created with
 Buffer.concat()" );
	script_tag( name: "affected", value: "'nodejs4' package(s) on SUSE Linux Enterprise Module for Web Scripting 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs4", rpm: "nodejs4~4.6.0~8.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-debuginfo", rpm: "nodejs4-debuginfo~4.6.0~8.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-debugsource", rpm: "nodejs4-debugsource~4.6.0~8.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-devel", rpm: "nodejs4-devel~4.6.0~8.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs4-docs", rpm: "nodejs4-docs~4.6.0~8.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm4", rpm: "npm4~4.6.0~8.1", rls: "SLES12.0" ) )){
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

