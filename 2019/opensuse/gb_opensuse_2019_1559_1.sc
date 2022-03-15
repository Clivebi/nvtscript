if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852558" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-5828", "CVE-2019-5829", "CVE-2019-5830", "CVE-2019-5831", "CVE-2019-5832", "CVE-2019-5833", "CVE-2019-5834", "CVE-2019-5835", "CVE-2019-5836", "CVE-2019-5837", "CVE-2019-5838", "CVE-2019-5839", "CVE-2019-5840" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-25 04:15:00 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-06-16 02:00:38 +0000 (Sun, 16 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2019:1559-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1559-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00033.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2019:1559-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for chromium to version 75.0.3770.80 fixes the following
  issues:

  Security issues fixed:

  - CVE-2019-5828: Fixed a Use after free in ServiceWorker

  - CVE-2019-5829: Fixed Use after free in Download Manager

  - CVE-2019-5830: Fixed an incorrectly credentialed requests in CORS

  - CVE-2019-5831: Fixed an incorrect map processing in V8

  - CVE-2019-5832: Fixed an incorrect CORS handling in XHR

  - CVE-2019-5833: Fixed an inconsistent security UI placemen

  - CVE-2019-5835: Fixed an out of bounds read in Swiftshader

  - CVE-2019-5836: Fixed a heap buffer overflow in Angle

  - CVE-2019-5837: Fixed a cross-origin resources size disclosure in Appcache

  - CVE-2019-5838: Fixed an overly permissive tab access in Extensions

  - CVE-2019-5839: Fixed an incorrect handling of certain code points in
  Blink

  - CVE-2019-5840: Fixed a popup blocker bypass

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1559=1" );
	script_tag( name: "affected", value: "'chromium' package(s) on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~75.0.3770.80~214.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~75.0.3770.80~214.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~75.0.3770.80~214.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~75.0.3770.80~214.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~75.0.3770.80~214.1", rls: "openSUSELeap42.3" ) )){
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

