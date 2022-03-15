if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852078" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_cve_id( "CVE-2017-7500" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:42:12 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for rpm (openSUSE-SU-2018:2215-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:2215-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00016.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rpm'
  package(s) announced via the openSUSE-SU-2018:2215-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rpm fixes the following issues:

  This security vulnerability was fixed:

  - CVE-2017-7500: Fixed symlink attacks during RPM installation (bsc#943457)


  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-808=1" );
	script_tag( name: "affected", value: "rpm on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-rpm-debugsource", rpm: "python-rpm-debugsource~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-rpm", rpm: "python2-rpm~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-rpm-debuginfo", rpm: "python2-rpm-debuginfo~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rpm", rpm: "python3-rpm~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-rpm-debuginfo", rpm: "python3-rpm-debuginfo~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm", rpm: "rpm~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-build", rpm: "rpm-build~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-build-debuginfo", rpm: "rpm-build-debuginfo~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-debuginfo", rpm: "rpm-debuginfo~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-debugsource", rpm: "rpm-debugsource~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-devel", rpm: "rpm-devel~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-32bit", rpm: "rpm-32bit~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pm-32bit-debuginfo", rpm: "pm-32bit-debuginfo~4.14.1~lp150.9.3.1", rls: "openSUSELeap15.0" ) )){
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

