if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852806" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2019-14822" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-27 15:15:00 +0000 (Thu, 27 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:32:02 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for ibus (openSUSE-SU-2019:2199-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2199-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00074.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ibus'
  package(s) announced via the openSUSE-SU-2019:2199-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ibus fixes the following issues:

  - CVE-2019-14822: Fixed misconfiguration of the DBus server allows to
  unprivileged user could monitor and send method calls to the ibus bus
  of another user (bsc#1150011).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2199=1" );
	script_tag( name: "affected", value: "'ibus' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "ibus", rpm: "ibus~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-debuginfo", rpm: "ibus-debuginfo~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-debugsource", rpm: "ibus-debugsource~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-devel", rpm: "ibus-devel~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-gtk", rpm: "ibus-gtk~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-gtk-debuginfo", rpm: "ibus-gtk-debuginfo~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-gtk3", rpm: "ibus-gtk3~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-gtk3-debuginfo", rpm: "ibus-gtk3-debuginfo~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libibus-1_0-5", rpm: "libibus-1_0-5~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libibus-1_0-5-debuginfo", rpm: "libibus-1_0-5-debuginfo~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-IBus-1_0", rpm: "typelib-1_0-IBus-1_0~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-gtk-32bit", rpm: "ibus-gtk-32bit~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-gtk-32bit-debuginfo", rpm: "ibus-gtk-32bit-debuginfo~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-gtk3-32bit", rpm: "ibus-gtk3-32bit~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-gtk3-32bit-debuginfo", rpm: "ibus-gtk3-32bit-debuginfo~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libibus-1_0-5-32bit", rpm: "libibus-1_0-5-32bit~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libibus-1_0-5-32bit-debuginfo", rpm: "libibus-1_0-5-32bit-debuginfo~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-ibus", rpm: "python-ibus~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ibus-lang", rpm: "ibus-lang~1.5.19~lp151.2.3.1", rls: "openSUSELeap15.1" ) )){
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

