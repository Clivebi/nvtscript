if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851650" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-24 07:29:54 +0100 (Fri, 24 Nov 2017)" );
	script_cve_id( "CVE-2017-15864", "CVE-2017-16664" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-08 18:57:00 +0000 (Wed, 08 May 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for otrs (openSUSE-SU-2017:3054-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'otrs'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for otrs fixes the following security issues:

  - CVE-2017-15864: Remote authenticated attackers could have caused otrs to
  disclose configuration information, including database credentials
  (boo#1068677, OSA-2017-06)

  - CVE-2017-16664: Remote authenticated attackers could have caused the
  execution of shell commands with the permission of the web server user
  (boo#1069391, OSA-2017-07)" );
	script_tag( name: "affected", value: "otrs on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:3054-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "otrs", rpm: "otrs~3.3.20~5.11.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "otrs-doc", rpm: "otrs-doc~3.3.20~5.11.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "otrs-itsm", rpm: "otrs-itsm~3.3.14~5.11.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "otrs", rpm: "otrs~3.3.20~14.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "otrs-doc", rpm: "otrs-doc~3.3.20~14.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "otrs-itsm", rpm: "otrs-itsm~3.3.14~14.1", rls: "openSUSELeap42.3" ) )){
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

