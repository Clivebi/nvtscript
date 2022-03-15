if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851642" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-07 11:06:30 +0100 (Tue, 07 Nov 2017)" );
	script_cve_id( "CVE-2017-14226" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-09 21:46:00 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for libwpd (openSUSE-SU-2017:2943-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libwpd'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libwpd fixes the following issues:

  Security issue fixed:

  - CVE-2017-14226: WP1StylesListener.cpp, WP5StylesListener.cpp, and
  WP42StylesListener.cpp in libwpd 0.10.1 mishandle iterators, which
  allows remote attackers to cause a denial of service (heap-based buffer
  over-read in the WPXTableList class in WPXTable.cpp). This vulnerability
  can be triggered in LibreOffice before 5.3.7. It may lead to suffering a
  remote attack against a LibreOffice application. (bnc#1058025)

  Bugfixes:

  - Fix various crashes, leaks and hangs when reading damaged files found by
  oss-fuzz.

  - Fix crash when NULL is passed as input stream.

  - Use symbol visibility on Linux. The library only exports public
  functions now.

  - Avoid infinite loop. (libwpd#3)

  - Remove bashism. (libwpd#5)

  - Fix various crashes and hangs when reading broken files found with the
  help of american-fuzzy-lop.

  - Make --help output of all command line tools more help2man-friendly.

  - Miscellaneous fixes and cleanups.

  - Generate manpages for the libwpd-tools

  This update was imported from the SUSE:SLE-12:Update update project." );
	script_tag( name: "affected", value: "libwpd on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:2943-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
	if(!isnull( res = isrpmvuln( pkg: "libwpd-0_10-10", rpm: "libwpd-0_10-10~0.10.2~5.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-0_10-10-debuginfo", rpm: "libwpd-0_10-10-debuginfo~0.10.2~5.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-debugsource", rpm: "libwpd-debugsource~0.10.2~5.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-devel", rpm: "libwpd-devel~0.10.2~5.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-tools", rpm: "libwpd-tools~0.10.2~5.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-tools-debuginfo", rpm: "libwpd-tools-debuginfo~0.10.2~5.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-devel-doc", rpm: "libwpd-devel-doc~0.10.2~5.3.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libwpd-devel-doc", rpm: "libwpd-devel-doc~0.10.2~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-0_10-10", rpm: "libwpd-0_10-10~0.10.2~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-0_10-10-debuginfo", rpm: "libwpd-0_10-10-debuginfo~0.10.2~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-debugsource", rpm: "libwpd-debugsource~0.10.2~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-devel", rpm: "libwpd-devel~0.10.2~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-tools", rpm: "libwpd-tools~0.10.2~8.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwpd-tools-debuginfo", rpm: "libwpd-tools-debuginfo~0.10.2~8.1", rls: "openSUSELeap42.3" ) )){
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

