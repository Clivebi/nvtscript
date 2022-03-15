if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851585" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-04 12:46:37 +0530 (Fri, 04 Aug 2017)" );
	script_cve_id( "CVE-2017-5091", "CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5094", "CVE-2017-5095", "CVE-2017-5096", "CVE-2017-5097", "CVE-2017-5098", "CVE-2017-5099", "CVE-2017-5100", "CVE-2017-5101", "CVE-2017-5102", "CVE-2017-5103", "CVE-2017-5104", "CVE-2017-5105", "CVE-2017-5106", "CVE-2017-5107", "CVE-2017-5108", "CVE-2017-5109", "CVE-2017-5110", "CVE-2017-7000" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2017:1993-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update Chromium to version 60.0.3112.78 fixes security issue and bugs.

  The following security issues were fixed:

  * CVE-2017-5091: Use after free in IndexedDB

  * CVE-2017-5092: Use after free in PPAPI

  * CVE-2017-5093: UI spoofing in Blink

  * CVE-2017-5094: Type confusion in extensions

  * CVE-2017-5095: Out-of-bounds write in PDFium

  * CVE-2017-5096: User information leak via Android intents

  * CVE-2017-5097: Out-of-bounds read in Skia

  * CVE-2017-5098: Use after free in V8

  * CVE-2017-5099: Out-of-bounds write in PPAPI

  * CVE-2017-5100: Use after free in Chrome Apps

  * CVE-2017-5101: URL spoofing in OmniBox

  * CVE-2017-5102: Uninitialized use in Skia

  * CVE-2017-5103: Uninitialized use in Skia

  * CVE-2017-5104: UI spoofing in browser

  * CVE-2017-7000: Pointer disclosure in SQLite

  * CVE-2017-5105: URL spoofing in OmniBox

  * CVE-2017-5106: URL spoofing in OmniBox

  * CVE-2017-5107: User information leak via SVG

  * CVE-2017-5108: Type confusion in PDFium

  * CVE-2017-5109: UI spoofing in browser

  * CVE-2017-5110: UI spoofing in payments dialog

  * Various fixes from internal audits, fuzzing and other initiatives

  A number of upstream bugfixes are also included in this release." );
	script_tag( name: "affected", value: "chromium on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:1993-1" );
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~60.0.3112.78~104.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~60.0.3112.78~104.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~60.0.3112.78~104.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~60.0.3112.78~104.21.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~60.0.3112.78~104.21.1", rls: "openSUSELeap42.2" ) )){
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

