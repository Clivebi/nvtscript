if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853448" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2020-14628", "CVE-2020-14629", "CVE-2020-14646", "CVE-2020-14647", "CVE-2020-14648", "CVE-2020-14649", "CVE-2020-14650", "CVE-2020-14673", "CVE-2020-14674", "CVE-2020-14675", "CVE-2020-14676", "CVE-2020-14677", "CVE-2020-14694", "CVE-2020-14695", "CVE-2020-14698", "CVE-2020-14699", "CVE-2020-14700", "CVE-2020-14703", "CVE-2020-14704", "CVE-2020-14707", "CVE-2020-14711", "CVE-2020-14712", "CVE-2020-14713", "CVE-2020-14714", "CVE-2020-14715" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 18:51:00 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-09-24 06:26:43 +0000 (Thu, 24 Sep 2020)" );
	script_name( "openSUSE: Security Advisory for virtualbox (openSUSE-SU-2020:1511-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1511-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00079.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2020:1511-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for virtualbox fixes the following issues:

  Version Bump to 6.0.24 (released July 14 2020 by Oracle)

  This is a maintenance release. The following items were fixed and/or added:

  - API: Fix unintentionally enabled audio due to a settings file version
  dependent bug

  - VBoxManage: Fix crash of 'VBoxManage internalcommands repairhd' when
  processing invalid input (bug #19579)

  - Guest Additions: Fix issues detecting guest additions ISO at runtime

  - Fixes CVE-2020-14628, CVE-2020-14646, CVE-2020-14647, CVE-2020-14649,
  CVE-2020-14713, CVE-2020-14674, CVE-2020-14675, CVE-2020-14676,
  CVE-2020-14677, CVE-2020-14699, CVE-2020-14711, CVE-2020-14629,
  CVE-2020-14703, CVE-2020-14704, CVE-2020-14648, CVE-2020-14650,
  CVE-2020-14673, CVE-2020-14694, CVE-2020-14695, CVE-2020-14698,
  CVE-2020-14700, CVE-2020-14712, CVE-2020-14707, CVE-2020-14714,
  CVE-2020-14715 boo#1174159


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1511=1" );
	script_tag( name: "affected", value: "'virtualbox' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "python3-virtualbox", rpm: "python3-virtualbox~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-virtualbox-debuginfo", rpm: "python3-virtualbox-debuginfo~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox", rpm: "virtualbox~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-debuginfo", rpm: "virtualbox-debuginfo~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-debugsource", rpm: "virtualbox-debugsource~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-devel", rpm: "virtualbox-devel~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-tools", rpm: "virtualbox-guest-tools~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-tools-debuginfo", rpm: "virtualbox-guest-tools-debuginfo~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-x11", rpm: "virtualbox-guest-x11~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-x11-debuginfo", rpm: "virtualbox-guest-x11-debuginfo~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-default", rpm: "virtualbox-kmp-default~6.0.24_k4.12.14_lp151.28.67~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-default-debuginfo", rpm: "virtualbox-kmp-default-debuginfo~6.0.24_k4.12.14_lp151.28.67~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-qt", rpm: "virtualbox-qt~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-qt-debuginfo", rpm: "virtualbox-qt-debuginfo~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-vnc", rpm: "virtualbox-vnc~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-websrv", rpm: "virtualbox-websrv~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-websrv-debuginfo", rpm: "virtualbox-websrv-debuginfo~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-desktop-icons", rpm: "virtualbox-guest-desktop-icons~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-source", rpm: "virtualbox-guest-source~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-host-source", rpm: "virtualbox-host-source~6.0.24~lp151.2.18.1", rls: "openSUSELeap15.1" ) )){
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

