if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851564" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-08 06:04:51 +0200 (Thu, 08 Jun 2017)" );
	script_cve_id( "CVE-2017-5070", "CVE-2017-5071", "CVE-2017-5072", "CVE-2017-5073", "CVE-2017-5074", "CVE-2017-5075", "CVE-2017-5076", "CVE-2017-5077", "CVE-2017-5078", "CVE-2017-5079", "CVE-2017-5080", "CVE-2017-5081", "CVE-2017-5082", "CVE-2017-5083", "CVE-2017-5085", "CVE-2017-5086" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2017:1502-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update to Chromium 59.0.3071.86 fixes
  the following security issues: - CVE-2017-5070: Type confusion in V8 -
  CVE-2017-5071: Out of bounds read in V8 - CVE-2017-5072: Address spoofing in
  Omnibox - CVE-2017-5073: Use after free in print preview - CVE-2017-5074: Use
  after free in Apps Bluetooth - CVE-2017-5075: Information leak in CSP reporting

  - CVE-2017-5086: Address spoofing in Omnibox - CVE-2017-5076: Address spoofing
  in Omnibox - CVE-2017-5077: Heap buffer overflow in Skia - CVE-2017-5078:
  Possible command injection in mailto handling - CVE-2017-5079: UI spoofing in
  Blink - CVE-2017-5080: Use after free in credit card autofill - CVE-2017-5081:
  Extension verification bypass - CVE-2017-5082: Insufficient hardening in credit
  card editor - CVE-2017-5083: UI spoofing in Blink - CVE-2017-5085: Inappropriate
  javascript execution on WebUI pages" );
	script_tag( name: "affected", value: "chromium on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:1502-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~59.0.3071.86~104.15.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~59.0.3071.86~104.15.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~59.0.3071.86~104.15.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~59.0.3071.86~104.15.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~59.0.3071.86~104.15.1", rls: "openSUSELeap42.2" ) )){
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

