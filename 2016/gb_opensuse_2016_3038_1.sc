if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851445" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-12-08 05:33:40 +0100 (Thu, 08 Dec 2016)" );
	script_cve_id( "CVE-2015-2181", "CVE-2016-5103" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for roundcubemail (openSUSE-SU-2016:3038-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'roundcubemail'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "roundcubemail was updated to version 1.1.7 and fixes the following issues:

  - Update to 1.1.7

  * A maliciously crafted FROM value could cause extra parameters to be
  passed to the sendmail command (boo#1012493)

  * A maliciously crafted email could cause untrusted code to be executed
  (cross site scripting using $lt area href=javascript:... )
  (boo#982003, CVE-2016-5103)

  * Avoid HTML styles that could cause potential click jacking
  (boo#1001856)

  - Update to 1.1.5

  * Fixed security issue in DBMail driver of password plugin
  (CVE-2015-2181, boo#976988)" );
	script_tag( name: "affected", value: "roundcubemail on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:3038-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "roundcubemail", rpm: "roundcubemail~1.1.7~15.1", rls: "openSUSELeap42.1" ) )){
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

