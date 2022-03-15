if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843320" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-05 11:54:58 +0530 (Thu, 05 Oct 2017)" );
	script_cve_id( "CVE-2017-7793", "CVE-2017-7810", "CVE-2017-7811", "CVE-2017-7812", "CVE-2017-7813", "CVE-2017-7814", "CVE-2017-7815", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7820", "CVE-2017-7822", "CVE-2017-7823", "CVE-2017-7824", "CVE-2017-7805", "CVE-2017-7816", "CVE-2017-7821" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-01 12:05:00 +0000 (Wed, 01 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for firefox USN-3435-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in
  Firefox. If a user were tricked in to opening a specially crafted website, an
  attacker could potentially exploit these to read uninitialized memory, obtain
  sensitive information, bypass phishing and malware protection, spoof the origin
  in modal dialogs, conduct cross-site scripting (XSS) attacks, cause a denial of
  service via application crash, or execute arbitrary code. (CVE-2017-7793,
  CVE-2017-7810, CVE-2017-7811, CVE-2017-7812, CVE-2017-7813, CVE-2017-7814,
  CVE-2017-7815, CVE-2017-7818, CVE-2017-7819, CVE-2017-7820, CVE-2017-7822,
  CVE-2017-7823, CVE-2017-7824) Martin Thomson discovered that NSS incorrectly
  generated handshake hashes. A remote attacker could potentially exploit this to
  cause a denial of service via application crash, or execute arbitrary code.
  (CVE-2017-7805) Multiple security issues were discovered in WebExtensions. If a
  user were tricked in to installing a specially crafted extension, an attacker
  could potentially exploit these to download and open non-executable files
  without interaction, or obtain elevated privileges. (CVE-2017-7816,
  CVE-2017-7821)" );
	script_tag( name: "affected", value: "firefox on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3435-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3435-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "firefox", ver: "56.0+build6-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "56.0+build6-0ubuntu0.17.04.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "56.0+build6-0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

