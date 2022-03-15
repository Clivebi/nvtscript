if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851948" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-25 06:00:36 +0200 (Thu, 25 Oct 2018)" );
	script_cve_id( "CVE-2018-17462", "CVE-2018-17463", "CVE-2018-17464", "CVE-2018-17465", "CVE-2018-17466", "CVE-2018-17467", "CVE-2018-17468", "CVE-2018-17469", "CVE-2018-17470", "CVE-2018-17471", "CVE-2018-17472", "CVE-2018-17473", "CVE-2018-17474", "CVE-2018-17475", "CVE-2018-17476", "CVE-2018-17477", "CVE-2018-5179" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for Chromium (openSUSE-SU-2018:3396-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for Chromium to version 70.0.3538.67 fixes multiple issues.

  Security issues fixed (bsc#1112111):

  - CVE-2018-17462: Sandbox escape in AppCache

  - CVE-2018-17463: Remote code execution in V8

  - Heap buffer overflow in Little CMS in PDFium

  - CVE-2018-17464: URL spoof in Omnibox

  - CVE-2018-17465: Use after free in V8

  - CVE-2018-17466: Memory corruption in Angle

  - CVE-2018-17467: URL spoof in Omnibox

  - CVE-2018-17468: Cross-origin URL disclosure in Blink

  - CVE-2018-17469: Heap buffer overflow in PDFium

  - CVE-2018-17470: Memory corruption in GPU Internals

  - CVE-2018-17471: Security UI occlusion in full screen mode

  - CVE-2018-17473: URL spoof in Omnibox

  - CVE-2018-17474: Use after free in Blink

  - CVE-2018-17475: URL spoof in Omnibox

  - CVE-2018-17476: Security UI occlusion in full screen mode

  - CVE-2018-5179: Lack of limits on update() in ServiceWorker

  - CVE-2018-17477: UI spoof in Extensions

  VAAPI hardware accelerated rendering is now enabled by default.

  This update contains the following packaging changes:

  - Use the system libusb-1.0 library

  - Use bundled harfbuzz library

  - Disable gnome-keyring to avoid crashes

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1253=1" );
	script_tag( name: "affected", value: "Chromium on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:3396-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00062.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~70.0.3538.67~179.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~70.0.3538.67~179.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~70.0.3538.67~179.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~70.0.3538.67~179.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~70.0.3538.67~179.1", rls: "openSUSELeap42.3" ) )){
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

