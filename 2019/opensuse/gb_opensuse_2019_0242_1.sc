if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852314" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2019-7443" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-10 14:00:00 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2019-02-26 04:11:53 +0100 (Tue, 26 Feb 2019)" );
	script_name( "openSUSE: Security Advisory for kauth (openSUSE-SU-2019:0242-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2019:0242-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00060.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kauth'
  package(s) announced via the openSUSE-SU-2019:0242-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kauth fixes the following issues:

  Security issue fixed:

  - CVE-2019-7443: Fixed an insecure handling of arguments in helpers by
  removing the support of passing gui variants (bsc#1124863).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-242=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-242=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-242=1" );
	script_tag( name: "affected", value: "kauth on openSUSE Leap 42.3, openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "kauth-debugsource", rpm: "kauth-debugsource~5.32.0~3.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kauth-devel", rpm: "kauth-devel~5.32.0~3.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libKF5Auth5", rpm: "libKF5Auth5~5.32.0~3.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libKF5Auth5-debuginfo", rpm: "libKF5Auth5-debuginfo~5.32.0~3.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kauth-devel-32bit", rpm: "kauth-devel-32bit~5.32.0~3.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libKF5Auth5-32bit", rpm: "libKF5Auth5-32bit~5.32.0~3.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libKF5Auth5-debuginfo-32bit", rpm: "libKF5Auth5-debuginfo-32bit~5.32.0~3.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libKF5Auth5-lang", rpm: "libKF5Auth5-lang~5.32.0~3.3.1", rls: "openSUSELeap42.3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "kauth-debugsource", rpm: "kauth-debugsource~5.45.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kauth-devel", rpm: "kauth-devel~5.45.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libKF5Auth5", rpm: "libKF5Auth5~5.45.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libKF5Auth5-debuginfo", rpm: "libKF5Auth5-debuginfo~5.45.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libKF5Auth5-lang", rpm: "libKF5Auth5-lang~5.45.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kauth-devel-32bit", rpm: "kauth-devel-32bit~5.45.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libKF5Auth5-32bit", rpm: "libKF5Auth5-32bit~5.45.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libKF5Auth5-32bit-debuginfo", rpm: "libKF5Auth5-32bit-debuginfo~5.45.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
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

