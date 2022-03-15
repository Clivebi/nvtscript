if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851406" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-10-12 05:46:13 +0200 (Wed, 12 Oct 2016)" );
	script_cve_id( "CVE-2016-1669", "CVE-2016-2178", "CVE-2016-2183", "CVE-2016-5325", "CVE-2016-6304", "CVE-2016-6306", "CVE-2016-7052", "CVE-2016-7099" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for nodejs (openSUSE-SU-2016:2496-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update brings the new upstream nodejs LTS version 4.6.0, fixing bugs
  and security issues:

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
	script_tag( name: "affected", value: "nodejs on openSUSE Leap 42.1, openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:2496-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "nodejs", rpm: "nodejs~4.6.0~24.2", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs-debuginfo", rpm: "nodejs-debuginfo~4.6.0~24.2", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs-debugsource", rpm: "nodejs-debugsource~4.6.0~24.2", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs-devel", rpm: "nodejs-devel~4.6.0~24.2", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs-doc", rpm: "nodejs-doc~4.6.0~24.2", rls: "openSUSE13.2" ) )){
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

