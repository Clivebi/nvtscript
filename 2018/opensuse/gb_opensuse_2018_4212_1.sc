if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852199" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_cve_id( "CVE-2018-19044", "CVE-2018-19045", "CVE-2018-19046" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 14:13:00 +0000 (Tue, 12 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-12-22 04:00:40 +0100 (Sat, 22 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for keepalived (openSUSE-SU-2018:4212-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2018:4212-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00053.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'keepalived'
  package(s) announced via the openSUSE-SU-2018:4212-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for keepalived to version 2.0.10 fixes the following issues:

  Security issues fixed (bsc#1015141):

  - CVE-2018-19044: Fixed a check for pathnames with symlinks when writing
  data to a temporary file upon a call to PrintData or PrintStats

  - CVE-2018-19045: Fixed mode when creating new temporary files upon a call
  to PrintData or PrintStats

  - CVE-2018-19046: Fixed a check for existing plain files when writing data
  to a temporary file upon a call to PrintData or PrintStats

  Non-security issues fixed:

  - Replace references to /var/adm/fillup-templates with new %_fillupdir
  macro (boo#1069468)

  - Use getaddrinfo instead of gethostbyname to workaround glibc
  gethostbyname function buffer overflow (bsc#949238)
  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1575=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1575=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1575=1" );
	script_tag( name: "affected", value: "keepalived on openSUSE Leap 42.3, openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "keepalived", rpm: "keepalived~2.0.10~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "keepalived-debuginfo", rpm: "keepalived-debuginfo~2.0.10~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "keepalived-debugsource", rpm: "keepalived-debugsource~2.0.10~7.3.1", rls: "openSUSELeap42.3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "keepalived", rpm: "keepalived~2.0.10~lp150.3.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "keepalived-debuginfo", rpm: "keepalived-debuginfo~2.0.10~lp150.3.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "keepalived-debugsource", rpm: "keepalived-debugsource~2.0.10~lp150.3.4.1", rls: "openSUSELeap15.0" ) )){
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

