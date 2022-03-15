if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853423" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2020-25032" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-21 12:15:00 +0000 (Wed, 21 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-10 03:00:39 +0000 (Thu, 10 Sep 2020)" );
	script_name( "openSUSE: Security Advisory for python-Flask-Cors (openSUSE-SU-2020:1393-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap15\\.2|openSUSELeap15\\.1)" );
	script_xref( name: "openSUSE-SU", value: "2020:1393-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00028.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-Flask-Cors'
  package(s) announced via the openSUSE-SU-2020:1393-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-Flask-Cors fixes the following issues:

  - CVE-2020-25032: fix a relative directory traversal vulnerability
  (bsc#1175986).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1393=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1393=1" );
	script_tag( name: "affected", value: "'python-Flask-Cors' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "python2-Flask-Cors", rpm: "python2-Flask-Cors~3.0.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-Flask-Cors", rpm: "python3-Flask-Cors~3.0.8~lp152.2.3.1", rls: "openSUSELeap15.2" ) )){
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "python2-Flask-Cors", rpm: "python2-Flask-Cors~3.0.7~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-Flask-Cors", rpm: "python3-Flask-Cors~3.0.7~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
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

