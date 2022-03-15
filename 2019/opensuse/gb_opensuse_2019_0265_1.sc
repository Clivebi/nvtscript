if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852320" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2018-15518", "CVE-2018-19873" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 09:15:00 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-02-28 04:07:28 +0100 (Thu, 28 Feb 2019)" );
	script_name( "openSUSE: Security Advisory for libqt5-qtbase (openSUSE-SU-2019:0265-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0265-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00074.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libqt5-qtbase'
  package(s) announced via the openSUSE-SU-2019:0265-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libqt5-qtbase provides the following fixes:

  Security issues fixed:

  - CVE-2018-15518: Fixed double free in QXmlStreamReader (bsc#1118595)

  - CVE-2018-19873: Fixed Denial of Service on malformed BMP file in
  QBmpHandler (bsc#1118596)

  Non-security issues fixed:

  - Fix dynamic loading of libGL. (bsc#1099874)

  - Make sure printer settings are properly remembered. (bsc#1096328)

  - Add patch to fix fails to load pixmap cursors on XRender less system
  (bsc#1108889)

  - Fix krita pop-up palette not working properly (bsc#1120639)


  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-265=1" );
	script_tag( name: "affected", value: "libqt5-qtbase on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libQt5Bootstrap-devel-static", rpm: "libQt5Bootstrap-devel-static~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent-devel", rpm: "libQt5Concurrent-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5", rpm: "libQt5Concurrent5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5-debuginfo", rpm: "libQt5Concurrent5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core-devel", rpm: "libQt5Core-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5", rpm: "libQt5Core5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5-debuginfo", rpm: "libQt5Core5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus-devel", rpm: "libQt5DBus-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus-devel-debuginfo", rpm: "libQt5DBus-devel-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5", rpm: "libQt5DBus5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5-debuginfo", rpm: "libQt5DBus5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui-devel", rpm: "libQt5Gui-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5", rpm: "libQt5Gui5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5-debuginfo", rpm: "libQt5Gui5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5KmsSupport-devel-static", rpm: "libQt5KmsSupport-devel-static~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network-devel", rpm: "libQt5Network-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5", rpm: "libQt5Network5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5-debuginfo", rpm: "libQt5Network5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL-devel", rpm: "libQt5OpenGL-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5", rpm: "libQt5OpenGL5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5-debuginfo", rpm: "libQt5OpenGL5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGLExtensions-devel-static", rpm: "libQt5OpenGLExtensions-devel-static~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PlatformHeaders-devel", rpm: "libQt5PlatformHeaders-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PlatformSupport-devel-static", rpm: "libQt5PlatformSupport-devel-static~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport-devel", rpm: "libQt5PrintSupport-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5", rpm: "libQt5PrintSupport5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5-debuginfo", rpm: "libQt5PrintSupport5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql-devel", rpm: "libQt5Sql-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5", rpm: "libQt5Sql5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-debuginfo", rpm: "libQt5Sql5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql", rpm: "libQt5Sql5-mysql~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql-debuginfo", rpm: "libQt5Sql5-mysql-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql", rpm: "libQt5Sql5-postgresql~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql-debuginfo", rpm: "libQt5Sql5-postgresql-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite", rpm: "libQt5Sql5-sqlite~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite-debuginfo", rpm: "libQt5Sql5-sqlite-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC", rpm: "libQt5Sql5-unixODBC~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC-debuginfo", rpm: "libQt5Sql5-unixODBC-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test-devel", rpm: "libQt5Test-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5", rpm: "libQt5Test5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5-debuginfo", rpm: "libQt5Test5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets-devel", rpm: "libQt5Widgets-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5", rpm: "libQt5Widgets5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5-debuginfo", rpm: "libQt5Widgets5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml-devel", rpm: "libQt5Xml-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5", rpm: "libQt5Xml5~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5-debuginfo", rpm: "libQt5Xml5-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-common-devel", rpm: "libqt5-qtbase-common-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-common-devel-debuginfo", rpm: "libqt5-qtbase-common-devel-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-debugsource", rpm: "libqt5-qtbase-debugsource~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-devel", rpm: "libqt5-qtbase-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-examples", rpm: "libqt5-qtbase-examples~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-examples-debuginfo", rpm: "libqt5-qtbase-examples-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-platformtheme-gtk3", rpm: "libqt5-qtbase-platformtheme-gtk3~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-platformtheme-gtk3-debuginfo", rpm: "libqt5-qtbase-platformtheme-gtk3-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Bootstrap-devel-static-32bit", rpm: "libQt5Bootstrap-devel-static-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent-devel-32bit", rpm: "libQt5Concurrent-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5-32bit", rpm: "libQt5Concurrent5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Concurrent5-32bit-debuginfo", rpm: "libQt5Concurrent5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core-devel-32bit", rpm: "libQt5Core-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5-32bit", rpm: "libQt5Core5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core5-32bit-debuginfo", rpm: "libQt5Core5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus-devel-32bit", rpm: "libQt5DBus-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus-devel-32bit-debuginfo", rpm: "libQt5DBus-devel-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5-32bit", rpm: "libQt5DBus5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus5-32bit-debuginfo", rpm: "libQt5DBus5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui-devel-32bit", rpm: "libQt5Gui-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5-32bit", rpm: "libQt5Gui5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui5-32bit-debuginfo", rpm: "libQt5Gui5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network-devel-32bit", rpm: "libQt5Network-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5-32bit", rpm: "libQt5Network5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network5-32bit-debuginfo", rpm: "libQt5Network5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL-devel-32bit", rpm: "libQt5OpenGL-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5-32bit", rpm: "libQt5OpenGL5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL5-32bit-debuginfo", rpm: "libQt5OpenGL5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGLExtensions-devel-static-32bit", rpm: "libQt5OpenGLExtensions-devel-static-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PlatformSupport-devel-static-32bit", rpm: "libQt5PlatformSupport-devel-static-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport-devel-32bit", rpm: "libQt5PrintSupport-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5-32bit", rpm: "libQt5PrintSupport5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport5-32bit-debuginfo", rpm: "libQt5PrintSupport5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql-devel-32bit", rpm: "libQt5Sql-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-32bit", rpm: "libQt5Sql5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-32bit-debuginfo", rpm: "libQt5Sql5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql-32bit", rpm: "libQt5Sql5-mysql-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-mysql-32bit-debuginfo", rpm: "libQt5Sql5-mysql-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql-32bit", rpm: "libQt5Sql5-postgresql-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-postgresql-32bit-debuginfo", rpm: "libQt5Sql5-postgresql-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite-32bit", rpm: "libQt5Sql5-sqlite-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-sqlite-32bit-debuginfo", rpm: "libQt5Sql5-sqlite-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC-32bit", rpm: "libQt5Sql5-unixODBC-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql5-unixODBC-32bit-debuginfo", rpm: "libQt5Sql5-unixODBC-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test-devel-32bit", rpm: "libQt5Test-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5-32bit", rpm: "libQt5Test5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test5-32bit-debuginfo", rpm: "libQt5Test5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets-devel-32bit", rpm: "libQt5Widgets-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5-32bit", rpm: "libQt5Widgets5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets5-32bit-debuginfo", rpm: "libQt5Widgets5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml-devel-32bit", rpm: "libQt5Xml-devel-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5-32bit", rpm: "libQt5Xml5-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Xml5-32bit-debuginfo", rpm: "libQt5Xml5-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-examples-32bit", rpm: "libqt5-qtbase-examples-32bit~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-examples-32bit-debuginfo", rpm: "libqt5-qtbase-examples-32bit-debuginfo~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Core-private-headers-devel", rpm: "libQt5Core-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5DBus-private-headers-devel", rpm: "libQt5DBus-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Gui-private-headers-devel", rpm: "libQt5Gui-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5KmsSupport-private-headers-devel", rpm: "libQt5KmsSupport-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Network-private-headers-devel", rpm: "libQt5Network-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5OpenGL-private-headers-devel", rpm: "libQt5OpenGL-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PlatformSupport-private-headers-devel", rpm: "libQt5PlatformSupport-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5PrintSupport-private-headers-devel", rpm: "libQt5PrintSupport-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Sql-private-headers-devel", rpm: "libQt5Sql-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Test-private-headers-devel", rpm: "libQt5Test-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libQt5Widgets-private-headers-devel", rpm: "libQt5Widgets-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqt5-qtbase-private-headers-devel", rpm: "libqt5-qtbase-private-headers-devel~5.9.4~lp150.5.4.1", rls: "openSUSELeap15.0" ) )){
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

