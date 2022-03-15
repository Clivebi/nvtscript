if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852211" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_cve_id( "CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-03 18:29:00 +0000 (Mon, 03 Jun 2019)" );
	script_tag( name: "creation_date", value: "2018-12-23 04:01:46 +0100 (Sun, 23 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for go1.10 (openSUSE-SU-2018:4255-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2018:4255-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00060.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'go1.10'
  package(s) announced via the openSUSE-SU-2018:4255-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for go1.10 fixes the following issues:

  Security vulnerabilities fixed:

  - CVE-2018-16873 (bsc#1118897): cmd/go: remote command execution during
  'go get -u'.

  - CVE-2018-16874 (bsc#1118898): cmd/go: directory traversal in 'go get'
  via curly braces in import paths

  - CVE-2018-16875 (bsc#1118899): crypto/x509: CPU denial of service

  Other issues fixed:

  - Fix build error with PIE linker flags on ppc64le. (bsc#1113978,
  bsc#1098017)

  - Review dependencies (requires, recommends and supports) (bsc#1082409)

  - Make profile.d/go.sh no longer set GOROOT=, in order to make switching
  between versions no longer break. This ends up removing the need for
  go.sh entirely (because GOPATH is also set automatically) (boo#1119634)

  - Fix a regression that broke go get for import path patterns containing
  '...' (bsc#1119706)

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1593=1" );
	script_tag( name: "affected", value: "go1.10 on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "go1.10", rpm: "go1.10~1.10.7~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.10-doc", rpm: "go1.10-doc~1.10.7~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "go1.10-race", rpm: "go1.10-race~1.10.7~5.1", rls: "openSUSELeap42.3" ) )){
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

