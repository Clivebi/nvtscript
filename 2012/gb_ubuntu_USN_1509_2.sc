if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1509-2/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841087" );
	script_version( "2019-05-24T11:20:30+0000" );
	script_tag( name: "last_modification", value: "2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)" );
	script_tag( name: "creation_date", value: "2012-07-19 10:45:15 +0530 (Thu, 19 Jul 2012)" );
	script_cve_id( "CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1509-2" );
	script_name( "Ubuntu Update for ubufox USN-1509-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1509-2" );
	script_tag( name: "affected", value: "ubufox on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1509-1 fixed vulnerabilities in Firefox. This update provides an updated
  ubufox package for use with the latest Firefox.

  Original advisory details:

  Benoit Jacob, Jesse Ruderman, Christian Holler, Bill McCloskey, Brian Smith,
  Gary Kwong, Christoph Diehl, Chris Jones, Brad Lassey, and Kyle Huey discovered
  memory safety issues affecting Firefox. If the user were tricked into opening a
  specially crafted page, an attacker could possibly exploit these to cause a
  denial of service via application crash, or potentially execute code with the
  privileges of the user invoking Firefox. (CVE-2012-1948, CVE-2012-1949)

  Mario Gomes discovered that the address bar may be incorrectly updated.
  Drag-and-drop events in the address bar may cause the address of the previous
  site to be displayed while a new page is loaded. An attacker could exploit this
  to conduct phishing attacks. (CVE-2012-1950)

  Abhishek Arya discovered four memory safety issues affecting Firefox. If the
  user were tricked into opening a specially crafted page, an attacker could
  possibly exploit these to cause a denial of service via application crash, or
  potentially execute code with the privileges of the user invoking Firefox.
  (CVE-2012-1951, CVE-2012-1952, CVE-2012-1953, CVE-2012-1954)

  Mariusz Mlynski discovered that the address bar may be incorrectly updated.
  Calls to history.forward and history.back could be used to navigate to a site
  while the address bar still displayed the previous site. A remote attacker
  could exploit this to conduct phishing attacks. (CVE-2012-1955)

  Mario Heiderich discovered that HTML <embed> tags were not filtered out of the
  HTML <description> of RSS feeds. A remote attacker could exploit this to
  conduct cross-site scripting (XSS) attacks via javascript execution in the HTML
  feed view. (CVE-2012-1957)

  Arthur Gerkis discovered a use-after-free vulnerability. If the user were
  tricked into opening a specially crafted page, an attacker could possibly
  exploit this to cause a denial of service via application crash, or potentially
  execute code with the privileges of the user invoking Firefox. (CVE-2012-1958)

  Bobby Holley discovered that same-compartment security wrappers (SCSW) could be
  bypassed to allow XBL access. If the user were tricked into opening a specially
  crafted page, an attacker could possibly exploit this to execute code with the
  privileges of the user invoking Firefox. (CVE-2012-1959)

  Tony Payne discovered an out-of-bounds memory read in Mozilla' ...

  Description truncated, please see the referenced URL(s) for more information." );
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
	if(( res = isdpkgvuln( pkg: "ubufox", ver: "2.1.1-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xul-ext-ubufox", ver: "2.1.1-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ubufox", ver: "2.1.1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xul-ext-ubufox", ver: "2.1.1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "ubufox", ver: "2.1.1-0ubuntu0.11.10.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xul-ext-ubufox", ver: "2.1.1-0ubuntu0.11.10.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "ubufox", ver: "2.1.1-0ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xul-ext-ubufox", ver: "2.1.1-0ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

