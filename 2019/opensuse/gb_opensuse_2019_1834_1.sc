if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852645" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2018-19802", "CVE-2019-1010222", "CVE-2019-1010223", "CVE-2019-1010224" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-26 13:15:00 +0000 (Fri, 26 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-08-07 02:07:32 +0000 (Wed, 07 Aug 2019)" );
	script_name( "openSUSE: Security Advisory for aubio (openSUSE-SU-2019:1834-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1834-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00003.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aubio'
  package(s) announced via the openSUSE-SU-2019:1834-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for aubio fixes the following issues:

  - CVE-2019-1010224: Fixed a denial of service (boo#1142435).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1834=1" );
	script_tag( name: "affected", value: "'aubio' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "aubio-debugsource", rpm: "aubio-debugsource~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aubio-tools", rpm: "aubio-tools~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aubio-tools-debuginfo", rpm: "aubio-tools-debuginfo~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaubio-devel", rpm: "libaubio-devel~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaubio5", rpm: "libaubio5~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaubio5-debuginfo", rpm: "libaubio5-debuginfo~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaubio5-32bit", rpm: "libaubio5-32bit~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaubio5-32bit-debuginfo", rpm: "libaubio5-32bit-debuginfo~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-aubio-debugsource", rpm: "python-aubio-debugsource~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-aubio", rpm: "python2-aubio~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-aubio-debuginfo", rpm: "python2-aubio-debuginfo~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-aubio", rpm: "python3-aubio~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-aubio-debuginfo", rpm: "python3-aubio-debuginfo~0.4.6~lp150.3.13.1", rls: "openSUSELeap15.0" ) )){
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

