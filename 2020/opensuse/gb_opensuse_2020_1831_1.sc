if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853558" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2020-16004", "CVE-2020-16005", "CVE-2020-16006", "CVE-2020-16007", "CVE-2020-16008", "CVE-2020-16009", "CVE-2020-16011" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-17 12:33:00 +0000 (Wed, 17 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-11-06 04:01:12 +0000 (Fri, 06 Nov 2020)" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2020:1831-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap15\\.2|openSUSELeap15\\.1)" );
	script_xref( name: "openSUSE-SU", value: "2020:1831-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00017.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2020:1831-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for chromium fixes the following issues:

  - Update to 86.0.4240.183 boo#1178375

  - CVE-2020-16004: Use after free in user interface.

  - CVE-2020-16005: Insufficient policy enforcement in ANGLE.

  - CVE-2020-16006: Inappropriate implementation in V8

  - CVE-2020-16007: Insufficient data validation in installer.

  - CVE-2020-16008: Stack buffer overflow in WebRTC.

  - CVE-2020-16009: Inappropriate implementation in V8.

  - CVE-2020-16011: Heap buffer overflow in UI on Windows.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1831=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1831=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2020-1831=1" );
	script_tag( name: "affected", value: "'chromium' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~86.0.4240.183~lp152.2.45.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~86.0.4240.183~lp152.2.45.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~86.0.4240.183~lp152.2.45.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~86.0.4240.183~lp152.2.45.1", rls: "openSUSELeap15.2" ) )){
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~86.0.4240.183~lp151.2.150.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~86.0.4240.183~lp151.2.150.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~86.0.4240.183~lp151.2.150.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~86.0.4240.183~lp151.2.150.1", rls: "openSUSELeap15.1" ) )){
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

