if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851508" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-22 15:17:28 +0100 (Wed, 22 Feb 2017)" );
	script_cve_id( "CVE-2016-5545", "CVE-2017-3290", "CVE-2017-3316", "CVE-2017-3332" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-04 17:55:00 +0000 (Mon, 04 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for virtualbox (openSUSE-SU-2017:0382-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'virtualbox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for virtualbox to version 5.1.14 fixes the following issues:

  These security issues were fixed:

  - CVE-2016-5545: Vulnerability in the GUI subcomponent of virtualbox
  allows unauthenticated attacker  unauthorized update, insert or delete
  access to some data as well as unauthorized read access to a subset of
  VirtualBox accessible data and unauthorized ability to cause a partial
  denial of service (bsc#1020856).

  - CVE-2017-3290: Vulnerability in the Shared Folder subcomponent of
  virtualbox allows high privileged attacker unauthorized creation,
  deletion or modification access to critical data and unauthorized
  ability to cause a hang or frequently repeatable crash (bsc#1020856).

  - CVE-2017-3316: Vulnerability in the GUI subcomponent of virtualbox
  allows high privileged attacker with network access via multiple
  protocols to compromise Oracle VM VirtualBox (bsc#1020856).

  - CVE-2017-3332: Vulnerability in the SVGA Emulation subcomponent of
  virtualbox allows low privileged attacker unauthorized creation,
  deletion or modification access to critical data and unauthorized
  ability to cause a hang or frequently repeatable crash (bsc#1020856).

  For other changes please read the changelog." );
	script_tag( name: "affected", value: "virtualbox on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:0382-1" );
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
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-desktop-icons", rpm: "virtualbox-guest-desktop-icons~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-host-source", rpm: "virtualbox-host-source~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-virtualbox", rpm: "python-virtualbox~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-virtualbox-debuginfo", rpm: "python-virtualbox-debuginfo~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox", rpm: "virtualbox~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-debuginfo", rpm: "virtualbox-debuginfo~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-debugsource", rpm: "virtualbox-debugsource~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-devel", rpm: "virtualbox-devel~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-kmp-default", rpm: "virtualbox-guest-kmp-default~5.1.14_k4.4.36_8~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-kmp-default-debuginfo", rpm: "virtualbox-guest-kmp-default-debuginfo~5.1.14_k4.4.36_8~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-tools", rpm: "virtualbox-guest-tools~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-tools-debuginfo", rpm: "virtualbox-guest-tools-debuginfo~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-x11", rpm: "virtualbox-guest-x11~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-x11-debuginfo", rpm: "virtualbox-guest-x11-debuginfo~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-host-kmp-default", rpm: "virtualbox-host-kmp-default~5.1.14_k4.4.36_8~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-host-kmp-default-debuginfo", rpm: "virtualbox-host-kmp-default-debuginfo~5.1.14_k4.4.36_8~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-qt", rpm: "virtualbox-qt~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-qt-debuginfo", rpm: "virtualbox-qt-debuginfo~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-websrv", rpm: "virtualbox-websrv~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-websrv-debuginfo", rpm: "virtualbox-websrv-debuginfo~5.1.14~9.2", rls: "openSUSELeap42.2" ) )){
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

