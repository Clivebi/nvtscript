if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851988" );
	script_version( "2021-06-28T02:00:39+0000" );
	script_cve_id( "CVE-2018-14598", "CVE-2018-14599", "CVE-2018-14600" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 02:00:39 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:29:10 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for libX11 (openSUSE-SU-2018:3012-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:3012-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00006.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libX11'
  package(s) announced via the openSUSE-SU-2018:3012-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libX11 fixes the following security issues:

  - CVE-2018-14599: The function XListExtensions was vulnerable to an
  off-by-one error caused by malicious server responses, leading to DoS or
  possibly unspecified other impact (bsc#1102062)

  - CVE-2018-14600: The function XListExtensions interpreted a variable as
  signed instead of unsigned, resulting in an out-of-bounds write (of up
  to 128 bytes), leading to DoS or remote code execution (bsc#1102068)

  - CVE-2018-14598: A malicious server could have sent a reply in which the
  first string overflows, causing a variable to be set to NULL that will
  be freed later
  on, leading to DoS (segmentation fault) (bsc#1102073)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1107=1" );
	script_tag( name: "affected", value: "libX11 on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libX11-6", rpm: "libX11-6~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-6-debuginfo", rpm: "libX11-6-debuginfo~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-debugsource", rpm: "libX11-debugsource~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-devel", rpm: "libX11-devel~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-xcb1", rpm: "libX11-xcb1~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-xcb1-debuginfo", rpm: "libX11-xcb1-debuginfo~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-6-32bit", rpm: "libX11-6-32bit~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-6-32bit-debuginfo", rpm: "libX11-6-32bit-debuginfo~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-devel-32bit", rpm: "libX11-devel-32bit~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-xcb1-32bit", rpm: "libX11-xcb1-32bit~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-xcb1-32bit-debuginfo", rpm: "libX11-xcb1-32bit-debuginfo~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libX11-data", rpm: "libX11-data~1.6.5~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

