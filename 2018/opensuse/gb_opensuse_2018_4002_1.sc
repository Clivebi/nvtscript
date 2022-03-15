if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852173" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_cve_id( "CVE-2018-3780" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:40:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-12-10 07:38:56 +0100 (Mon, 10 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for nextcloud (openSUSE-SU-2018:4002-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2018:4002-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00002.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nextcloud'
  package(s) announced via the openSUSE-SU-2018:4002-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nextcloud fixes security issues and bugs.

  Security issues fixed:

  - CVE-2018-3780: Stored XSS in autocomplete suggestions for file comments
  (boo#1114817)

  This update also contains all bug fixes and improvements in the 13.0.8
  version, including:

  - Password expiration time changed from 12h to 7d

  - Bug fixes to the OAuth brute force protection

  - Various other bug fixes and improvements

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1487=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1487=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1487=1" );
	script_tag( name: "affected", value: "nextcloud on openSUSE Leap 42.3, openSUSE Leap 15.0." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "nextcloud", rpm: "nextcloud~13.0.8~15.1", rls: "openSUSELeap42.3" ) )){
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "nextcloud", rpm: "nextcloud~13.0.8~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
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

