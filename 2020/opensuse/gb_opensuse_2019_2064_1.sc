if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852932" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2019-7164", "CVE-2019-7548" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:46:34 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for python-SQLAlchemy (openSUSE-SU-2019:2064-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2064-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00010.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-SQLAlchemy'
  package(s) announced via the openSUSE-SU-2019:2064-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-SQLAlchemy fixes the following issues:

  Security issues fixed:

  - CVE-2019-7164: Fixed SQL Injection via the order_by parameter
  (bsc#1124593).

  - CVE-2019-7548: Fixed SQL Injection via the group_by parameter
  (bsc#1124593).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2064=1" );
	script_tag( name: "affected", value: "'python-SQLAlchemy' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "python-SQLAlchemy-doc", rpm: "python-SQLAlchemy-doc~1.2.14~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-SQLAlchemy-debuginfo", rpm: "python-SQLAlchemy-debuginfo~1.2.14~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-SQLAlchemy-debugsource", rpm: "python-SQLAlchemy-debugsource~1.2.14~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-SQLAlchemy", rpm: "python2-SQLAlchemy~1.2.14~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-SQLAlchemy-debuginfo", rpm: "python2-SQLAlchemy-debuginfo~1.2.14~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-SQLAlchemy", rpm: "python3-SQLAlchemy~1.2.14~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-SQLAlchemy-debuginfo", rpm: "python3-SQLAlchemy-debuginfo~1.2.14~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
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

