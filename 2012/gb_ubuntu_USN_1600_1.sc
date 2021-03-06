if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1600-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841181" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-11 10:04:22 +0530 (Thu, 11 Oct 2012)" );
	script_cve_id( "CVE-2012-3982", "CVE-2012-3983", "CVE-2012-3988", "CVE-2012-3989", "CVE-2012-3984", "CVE-2012-3985", "CVE-2012-3986", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-4184", "CVE-2012-3990", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1600-1" );
	script_name( "Ubuntu Update for firefox USN-1600-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1600-1" );
	script_tag( name: "affected", value: "firefox on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Henrik Skupin, Jesse Ruderman, Christian Holler, Soroush Dalili and others
  discovered several memory corruption flaws in Firefox. If a user were
  tricked into opening a specially crafted web page, a remote attacker could
  cause Firefox to crash or potentially execute arbitrary code as the user
  invoking the program. (CVE-2012-3982, CVE-2012-3983, CVE-2012-3988,
  CVE-2012-3989)

  David Bloom and Jordi Chancel discovered that Firefox did not always
  properly handle the <select> element. A remote attacker could exploit this
  to conduct URL spoofing and clickjacking attacks. (CVE-2012-3984)

  Collin Jackson discovered that Firefox did not properly follow the HTML5
  specification for document.domain behavior. A remote attacker could exploit
  this to conduct cross-site scripting (XSS) attacks via javascript
  execution. (CVE-2012-3985)

  Johnny Stenback discovered that Firefox did not properly perform security
  checks on tests methods for DOMWindowUtils. (CVE-2012-3986)

  Alice White discovered that the security checks for GetProperty could be
  bypassed when using JSAPI. If a user were tricked into opening a specially
  crafted web page, a remote attacker could exploit this to execute arbitrary
  code as the user invoking the program. (CVE-2012-3991)

  Mariusz Mlynski discovered a history state error in Firefox. A remote
  attacker could exploit this to spoof the location property to inject script
  or intercept posted data. (CVE-2012-3992)

  Mariusz Mlynski and others discovered several flays in Firefox that allowed
  a remote attacker to conduct cross-site scripting (XSS) attacks.
  (CVE-2012-3993, CVE-2012-3994, CVE-2012-4184)

  Abhishek Arya, Atte Kettunen and others discovered several memory flaws in
  Firefox when using the Address Sanitizer tool. If a user were tricked into
  opening a specially crafted web page, a remote attacker could cause Firefox
  to crash or potentially execute arbitrary code as the user invoking the
  program. (CVE-2012-3990, CVE-2012-3995, CVE-2012-4179, CVE-2012-4180,
  CVE-2012-4181, CVE-2012-4182, CVE-2012-4183, CVE-2012-4185, CVE-2012-4186,
  CVE-2012-4187, CVE-2012-4188)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "16.0+build1-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "16.0+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "16.0+build1-0ubuntu0.11.10.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "16.0+build1-0ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

