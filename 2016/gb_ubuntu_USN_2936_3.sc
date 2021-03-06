if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842770" );
	script_version( "2021-09-20T11:23:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:23:55 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-19 05:21:16 +0200 (Thu, 19 May 2016)" );
	script_cve_id( "CVE-2016-2804", "CVE-2016-2806", "CVE-2016-2807", "CVE-2016-2808", "CVE-2016-2811", "CVE-2016-2812", "CVE-2016-2814", "CVE-2016-2816", "CVE-2016-2817", "CVE-2016-2820" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for firefox USN-2936-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2936-1 fixed vulnerabilities in Firefox.
  The update caused an issue where a device update POST request was sent every time
  about:preferences sync was shown.
  This update fixes the problem.

  Original advisory details:

  Christian Holler, Tyson Smith, Phil Ringalda, Gary Kwong, Jesse Ruderman,
  Mats Palmgren, Carsten Book, Boris Zbarsky, David Bolter, Randell Jesup,
  Andrew McCreight, and Steve Fink discovered multiple memory safety issues
  in Firefox. If a user were tricked in to opening a specially crafted
  website, an attacker could potentially exploit these to cause a denial of
  service via application crash, or execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2016-2804, CVE-2016-2806,
  CVE-2016-2807)

  An invalid write was discovered when using the JavaScript .watch() method in
  some circumstances. If a user were tricked in to opening a specially crafted
  website, an attacker could potentially exploit this to cause a denial of
  service via application crash, or execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2016-2808)

  Looben Yang discovered a use-after-free and buffer overflow in service
  workers. If a user were tricked in to opening a specially crafted website,
  an attacker could potentially exploit these to cause a denial of service
  via application crash, or execute arbitrary code with the privileges of
  the user invoking Firefox. (CVE-2016-2811, CVE-2016-2812)

  Sascha Just discovered a buffer overflow in libstagefright in some
  circumstances. If a user were tricked in to opening a specially crafted
  website, an attacker could potentially exploit this to cause a denial of
  service via application crash, or execute arbitrary code with the
  privileges of the user invoking Firefox. (CVE-2016-2814)

  Muneaki Nishimura discovered that CSP is not applied correctly to web
  content sent with the multipart/x-mixed-replace MIME type. An attacker
  could potentially exploit this to conduct cross-site scripting (XSS)
  attacks when they would otherwise be prevented. (CVE-2016-2816)

  Muneaki Nishimura discovered that the chrome.tabs.update API for web
  extensions allows for navigation to javascript: URLs. A malicious
  extension could potentially exploit this to conduct cross-site scripting
  (XSS) attacks. (CVE-2016-2817)

  Mark Goodwin discovered that about:healthreport accepts certain events
  from any content present in the remote-report iframe. If another
  vulnerability allowed the injection of web content in the remote-report
  iframe, an attacker could potentially exploit this to change the user's
  sharing preferences. (CVE-2016-2820)" );
	script_tag( name: "affected", value: "firefox on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2936-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2936-3/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|16\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "46.0.1+build1-0ubuntu0.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "46.0.1+build1-0ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "46.0.1+build1-0ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "46.0.1+build1-0ubuntu0.15.10.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

