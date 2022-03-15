if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852223" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2018-5804", "CVE-2018-5813", "CVE-2018-5815", "CVE-2018-5816" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-10 19:30:00 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-01-11 04:00:53 +0100 (Fri, 11 Jan 2019)" );
	script_name( "openSUSE: Security Advisory for libraw (openSUSE-SU-2019:0008-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0008-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-01/msg00003.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libraw'
  package(s) announced via the openSUSE-SU-2019:0008-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libraw fixes the following issues:

  The following security vulnerabilities were addressed:

  - CVE-2018-5813: Fixed an error within the 'parse_minolta()' function
  (dcraw/dcraw.c) that could be exploited to trigger an infinite loop via
  a specially crafted file. This could be exploited to cause a
  DoS.(boo#1103200).

  - CVE-2018-5815: Fixed an integer overflow in the
  internal/dcraw_common.cpp:parse_qt() function, that could be exploited
  to cause an infinite loop via a specially crafted Apple QuickTime file.
  (boo#1103206)

  - CVE-2018-5804, CVE-2018-5816: Fixed a type confusion error in the
  identify function (bsc#1097975)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-8=1" );
	script_tag( name: "affected", value: "libraw on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libraw-debuginfo", rpm: "libraw-debuginfo~0.18.9~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libraw-debugsource", rpm: "libraw-debugsource~0.18.9~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libraw-devel", rpm: "libraw-devel~0.18.9~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libraw-devel-static", rpm: "libraw-devel-static~0.18.9~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libraw-tools", rpm: "libraw-tools~0.18.9~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libraw-tools-debuginfo", rpm: "libraw-tools-debuginfo~0.18.9~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libraw16", rpm: "libraw16~0.18.9~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libraw16-debuginfo", rpm: "libraw16-debuginfo~0.18.9~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

