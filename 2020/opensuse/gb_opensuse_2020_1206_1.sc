if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853358" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2020-6542", "CVE-2020-6543", "CVE-2020-6544", "CVE-2020-6545", "CVE-2020-6546", "CVE-2020-6547", "CVE-2020-6548", "CVE-2020-6549", "CVE-2020-6550", "CVE-2020-6551", "CVE-2020-6552", "CVE-2020-6553", "CVE-2020-6554", "CVE-2020-6555" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-27 20:15:00 +0000 (Wed, 27 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-08-15 03:00:45 +0000 (Sat, 15 Aug 2020)" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2020:1206-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap15\\.2|openSUSELeap15\\.1)" );
	script_xref( name: "openSUSE-SU", value: "2020:1206-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00034.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2020:1206-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for chromium fixes the following issues:

  - Chromium updated to 84.0.4147.125 (boo#1175085)

  * CVE-2020-6542: Use after free in ANGLE

  * CVE-2020-6543: Use after free in task scheduling

  * CVE-2020-6544: Use after free in media

  * CVE-2020-6545: Use after free in audio

  * CVE-2020-6546: Inappropriate implementation in installer

  * CVE-2020-6547: Incorrect security UI in media

  * CVE-2020-6548: Heap buffer overflow in Skia

  * CVE-2020-6549: Use after free in media

  * CVE-2020-6550: Use after free in IndexedDB

  * CVE-2020-6551: Use after free in WebXR

  * CVE-2020-6552: Use after free in Blink

  * CVE-2020-6553: Use after free in offline mode

  * CVE-2020-6554: Use after free in extensions

  * CVE-2020-6555: Out of bounds read in WebGL

  * Various fixes from internal audits, fuzzing and other initiatives

  - Disable wayland everywhere as it breaks headless and middle mouse copy
  everywhere: boo#1174497 boo#1175044


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1206=1

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1206=1" );
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~84.0.4147.125~lp152.2.12.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~84.0.4147.125~lp152.2.12.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~84.0.4147.125~lp152.2.12.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~84.0.4147.125~lp152.2.12.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~84.0.4147.125~lp152.2.12.2", rls: "openSUSELeap15.2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~84.0.4147.125~lp151.2.115.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~84.0.4147.125~lp151.2.115.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~84.0.4147.125~lp151.2.115.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~84.0.4147.125~lp151.2.115.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~84.0.4147.125~lp151.2.115.1", rls: "openSUSELeap15.1" ) )){
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

