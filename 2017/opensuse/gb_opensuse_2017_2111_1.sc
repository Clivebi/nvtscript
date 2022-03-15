if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851588" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-10 07:30:06 +0200 (Thu, 10 Aug 2017)" );
	script_cve_id( "CVE-2017-7435", "CVE-2017-7436", "CVE-2017-9269" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for libzypp (openSUSE-SU-2017:2111-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libzypp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Software Update Stack was updated to receive fixes and enhancements.

  libzypp:

  Security issues fixed:

  - CVE-2017-7435, CVE-2017-7436, CVE-2017-9269: Fix GPG check workflows,
  mainly for unsigned repositories and packages. (bsc#1045735, bsc#1038984)

  Bug fixes:

  - Re-probe on refresh if the repository type changes. (bsc#1048315)

  - Propagate proper error code to DownloadProgressReport. (bsc#1047785)

  - Allow to trigger an appdata refresh unconditionally. (bsc#1009745)

  - Support custom repo variables defined in /etc/zypp/vars.d.

  - Adapt loop mounting of ISO images. (bsc#1038132, bsc#1033236)

  - Fix potential crash if repository has no baseurl. (bsc#1043218)

  zypper:

  - Adapt download callback to report and handle unsigned packages.
  (bsc#1038984)

  - Report missing/optional files as 'not found' rather than 'error'.
  (bsc#1047785)

  - Document support for custom repository variables defined in
  /etc/zypp/vars.d.

  - Emphasize that it depends on how fast PackageKit will respond to a
  'quit' request sent if PK blocks package management.

  This update was imported from the SUSE:SLE-12-SP2:Update update project." );
	script_tag( name: "affected", value: "libzypp, on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:2111-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
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
	if(!isnull( res = isrpmvuln( pkg: "libzypp", rpm: "libzypp~16.15.2~5.9.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-debuginfo", rpm: "libzypp-debuginfo~16.15.2~5.9.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-debugsource", rpm: "libzypp-debugsource~16.15.2~5.9.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-devel", rpm: "libzypp-devel~16.15.2~5.9.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzypp-devel-doc", rpm: "libzypp-devel-doc~16.15.2~5.9.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper", rpm: "zypper~1.13.30~5.9.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-debuginfo", rpm: "zypper-debuginfo~1.13.30~5.9.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-debugsource", rpm: "zypper-debugsource~1.13.30~5.9.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-aptitude", rpm: "zypper-aptitude~1.13.30~5.9.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zypper-log", rpm: "zypper-log~1.13.30~5.9.1", rls: "openSUSELeap42.2" ) )){
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

