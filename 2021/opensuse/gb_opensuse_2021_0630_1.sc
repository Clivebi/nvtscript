if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853790" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2021-2074", "CVE-2021-2129", "CVE-2021-2264" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-27 01:40:00 +0000 (Wed, 27 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-05-01 03:02:19 +0000 (Sat, 01 May 2021)" );
	script_name( "openSUSE: Security Advisory for virtualbox (openSUSE-SU-2021:0630-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0630-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2RTNW7ZRCP2VD6YMPAHFC7MY4YIB5GTL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2021:0630-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for virtualbox fixes the following issues:

  - Version bump to 6.1.20 (released April 20 2021 by Oracle) Fixes
       boo#1183329 'virtualbox 6.1.18 crashes when it runs nested VM' Fixes
       boo#1183125 'Leap 15.3 installation in Virtualbox without VBox
       integration' Fixes CVE-2021-2264 and boo#1184542. The directory for the
        user .start files for autostarting VMs is moved from /etc/vbox to
       /etc/vbox/autostart.d. In addition, the autostart service is hardened
       (by Oracle).

  - change the modalias for guest-tools and guest-x11 to get them to
        autoinstall.

  - Own %{_sysconfdir}/X11/xinit/xinitrc.d as default packages (eg systemd)
       no longer do so, breaking package build.

  - Update fixes_for_leap15.3 for kernel API changes between 5.3.18-45 and
       5.3.18-47.

  - Add code to generate guest modules for Leap 15.2 and Leap 15.3. The
       kernel versions do not allow window resizing. Files
       'virtualbox-kmp-files-leap' and 'vboxguestconfig.sh' are added

  - Fixes CVE-2021-2074, boo#1181197 and CVE-2021-2129, boo#1181198.

  - Under some circumstances, shared folders are mounted as root." );
	script_tag( name: "affected", value: "'virtualbox' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-desktop-icons", rpm: "virtualbox-guest-desktop-icons~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-source", rpm: "virtualbox-guest-source~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-host-source", rpm: "virtualbox-host-source~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-virtualbox", rpm: "python3-virtualbox~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-virtualbox-debuginfo", rpm: "python3-virtualbox-debuginfo~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox", rpm: "virtualbox~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-debuginfo", rpm: "virtualbox-debuginfo~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-debugsource", rpm: "virtualbox-debugsource~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-devel", rpm: "virtualbox-devel~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-tools", rpm: "virtualbox-guest-tools~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-tools-debuginfo", rpm: "virtualbox-guest-tools-debuginfo~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-x11", rpm: "virtualbox-guest-x11~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-guest-x11-debuginfo", rpm: "virtualbox-guest-x11-debuginfo~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-debugsource", rpm: "virtualbox-kmp-debugsource~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-default", rpm: "virtualbox-kmp-default~6.1.20_k5.3.18_lp152.72~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-default-debuginfo", rpm: "virtualbox-kmp-default-debuginfo~6.1.20_k5.3.18_lp152.72~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-preempt", rpm: "virtualbox-kmp-preempt~6.1.20_k5.3.18_lp152.72~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-kmp-preempt-debuginfo", rpm: "virtualbox-kmp-preempt-debuginfo~6.1.20_k5.3.18_lp152.72~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-qt", rpm: "virtualbox-qt~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-qt-debuginfo", rpm: "virtualbox-qt-debuginfo~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-vnc", rpm: "virtualbox-vnc~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-websrv", rpm: "virtualbox-websrv~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "virtualbox-websrv-debuginfo", rpm: "virtualbox-websrv-debuginfo~6.1.20~lp152.2.21.1", rls: "openSUSELeap15.2" ) )){
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

