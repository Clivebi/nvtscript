if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852494" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2016-10745", "CVE-2019-10906", "CVE-2019-8341" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 15:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-05-14 02:00:52 +0000 (Tue, 14 May 2019)" );
	script_name( "openSUSE: Security Advisory for python-Jinja2 (openSUSE-SU-2019:1395-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1395-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00030.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-Jinja2'
  package(s) announced via the openSUSE-SU-2019:1395-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-Jinja2 to version 2.10.1 fixes the following issues:

  Security issues fixed:

  - CVE-2019-8341: Fixed a command injection in from_string() (bsc#1125815).

  - CVE-2019-10906: Fixed a sandbox escape due to information disclosure via
  str.format (bsc#1132323).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1395=1" );
	script_tag( name: "affected", value: "'python-Jinja2' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "python-Jinja2-emacs", rpm: "python-Jinja2-emacs~2.10.1~lp150.2.4.8", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-Jinja2-vim", rpm: "python-Jinja2-vim~2.10.1~lp150.2.4.8", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-Jinja2", rpm: "python2-Jinja2~2.10.1~lp150.2.4.8", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-Jinja2", rpm: "python3-Jinja2~2.10.1~lp150.2.4.8", rls: "openSUSELeap15.0" ) )){
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

