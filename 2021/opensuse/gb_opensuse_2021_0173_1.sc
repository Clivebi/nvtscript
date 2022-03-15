if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853636" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2020-16044", "CVE-2021-21117", "CVE-2021-21118", "CVE-2021-21119", "CVE-2021-21120", "CVE-2021-21121", "CVE-2021-21122", "CVE-2021-21123", "CVE-2021-21124", "CVE-2021-21125", "CVE-2021-21126", "CVE-2021-21127", "CVE-2021-21128", "CVE-2021-21129", "CVE-2021-21130", "CVE-2021-21131", "CVE-2021-21132", "CVE-2021-21133", "CVE-2021-21134", "CVE-2021-21135", "CVE-2021-21136", "CVE-2021-21137", "CVE-2021-21138", "CVE-2021-21139", "CVE-2021-21140", "CVE-2021-21141" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-11 21:06:00 +0000 (Thu, 11 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:57:33 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2021:0173-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0173-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GKJ4GOW4YBBVDHM3PN6ELURRBVPFRRJA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:0173-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for chromium fixes the following issues:

     chromium was updated to 88.0.4324.96 boo#1181137

  - CVE-2021-21117: Insufficient policy enforcement in Cryptohome

  - CVE-2021-21118: Insufficient data validation in V8

  - CVE-2021-21119: Use after free in Media

  - CVE-2021-21120: Use after free in WebSQL

  - CVE-2021-21121: Use after free in Omnibox

  - CVE-2021-21122: Use after free in Blink

  - CVE-2021-21123: Insufficient data validation in File System API

  - CVE-2021-21124: Potential user after free in Speech Recognizer

  - CVE-2021-21125: Insufficient policy enforcement in File System API

  - CVE-2020-16044: Use after free in WebRTC

  - CVE-2021-21126: Insufficient policy enforcement in extensions

  - CVE-2021-21127: Insufficient policy enforcement in extensions

  - CVE-2021-21128: Heap buffer overflow in Blink

  - CVE-2021-21129: Insufficient policy enforcement in File System API

  - CVE-2021-21130: Insufficient policy enforcement in File System API

  - CVE-2021-21131: Insufficient policy enforcement in File System API

  - CVE-2021-21132: Inappropriate implementation in DevTools

  - CVE-2021-21133: Insufficient policy enforcement in Downloads

  - CVE-2021-21134: Incorrect security UI in Page Info

  - CVE-2021-21135: Inappropriate implementation in Performance API

  - CVE-2021-21136: Insufficient policy enforcement in WebView

  - CVE-2021-21137: Inappropriate implementation in DevTools

  - CVE-2021-21138: Use after free in DevTools

  - CVE-2021-21139: Inappropriate implementation in iframe sandbox

  - CVE-2021-21140: Uninitialized Use in USB

  - CVE-2021-21141: Insufficient policy enforcement in File System API" );
	script_tag( name: "affected", value: "'chromium' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~88.0.4324.96~lp152.2.66.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~88.0.4324.96~lp152.2.66.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~88.0.4324.96~lp152.2.66.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~88.0.4324.96~lp152.2.66.1", rls: "openSUSELeap15.2" ) )){
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

