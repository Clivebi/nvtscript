if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853570" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_cve_id( "CVE-2020-17489" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 14:46:00 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-11-08 04:01:03 +0000 (Sun, 08 Nov 2020)" );
	script_name( "openSUSE: Security Advisory for gnome-settings-daemon, (openSUSE-SU-2020:1861-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1861-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00028.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnome-settings-daemon, '
  package(s) announced via the openSUSE-SU-2020:1861-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gnome-settings-daemon, gnome-shell fixes the following
  issues:

  gnome-settings-daemon:

  - Add support for recent UCM related changes in ALSA and PulseAudio.
  (jsc#SLE-16518)

  - Don't warn when a default source or sink is missing and the PulseAudio
  daemon is restarting. (jsc#SLE-16518)

  - Don't warn about starting/stopping services which don't exist.
  (bsc#1172760).

  gnome-shell:

  - Add support for recent UCM related changes in ALSA and PulseAudio.
  (jsc#SLE-16518)

  - CVE-2020-17489: reset auth prompt on vt switch before fade in
  loginDialog (bsc#1175155).

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1861=1" );
	script_tag( name: "affected", value: "'gnome-settings-daemon, ' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "gnome-settings-daemon-lang", rpm: "gnome-settings-daemon-lang~3.34.2+0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-shell-lang", rpm: "gnome-shell-lang~3.34.5~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-settings-daemon", rpm: "gnome-settings-daemon~3.34.2+0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-settings-daemon-debuginfo", rpm: "gnome-settings-daemon-debuginfo~3.34.2+0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-settings-daemon-debugsource", rpm: "gnome-settings-daemon-debugsource~3.34.2+0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-settings-daemon-devel", rpm: "gnome-settings-daemon-devel~3.34.2+0~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-shell", rpm: "gnome-shell~3.34.5~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-shell-calendar", rpm: "gnome-shell-calendar~3.34.5~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-shell-calendar-debuginfo", rpm: "gnome-shell-calendar-debuginfo~3.34.5~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-shell-debuginfo", rpm: "gnome-shell-debuginfo~3.34.5~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-shell-debugsource", rpm: "gnome-shell-debugsource~3.34.5~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-shell-devel", rpm: "gnome-shell-devel~3.34.5~lp152.2.9.1", rls: "openSUSELeap15.2" ) )){
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

