if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841427" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-05-17 09:54:38 +0530 (Fri, 17 May 2013)" );
	script_cve_id( "CVE-2013-0801", "CVE-2013-1669", "CVE-2013-1670", "CVE-2013-1671", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for firefox USN-1822-1" );
	script_xref( name: "USN", value: "1822-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1822-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|12\\.10|13\\.04)" );
	script_tag( name: "affected", value: "firefox on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Multiple memory safety issues were discovered in Firefox. If the user were
  tricked into opening a specially crafted page, an attacker could possibly
  exploit these to cause a denial of service via application crash, or
  potentially execute code with the privileges of the user invoking Firefox.
  (CVE-2013-0801, CVE-2013-1669)

  Cody Crews discovered that some constructors could be used to bypass
  restrictions enforced by their Chrome Object Wrapper (COW). An attacker
  could exploit this to conduct cross-site scripting (XSS) attacks.
  (CVE-2013-1670)

  It was discovered that the file input element could expose the full local
  path under certain conditions. An attacker could potentially exploit this
  to steal sensitive information. (CVE-2013-1671)

  A use-after-free was discovered when resizing video content whilst it is
  playing. An attacker could potentially exploit this to execute code with
  the privileges of the user invoking Firefox. (CVE-2013-1674)

  It was discovered that some DOMSVGZoomEvent functions could be used
  without being properly initialized, which could lead to information
  leakage. (CVE-2013-1675)

  Abhishek Arya discovered multiple memory safety issues in Firefox. If
  the user were tricked into opening a specially crafted page, an attacker
  could possibly exploit these to cause a denial of service via application
  crash, or potentially execute code with the privileges of the user
  invoking Firefox. (CVE-2013-1676, CVE-2013-1677, CVE-2013-1678,
  CVE-2013-1679, CVE-2013-1680, CVE-2013-1681)" );
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
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "21.0+build2-0ubuntu0.12.04.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "21.0+build2-0ubuntu0.12.10", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "21.0+build2-0ubuntu0.13.04", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

