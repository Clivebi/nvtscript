if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1729-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841329" );
	script_version( "2020-08-11T09:13:39+0000" );
	script_tag( name: "last_modification", value: "2020-08-11 09:13:39 +0000 (Tue, 11 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-02-22 10:12:50 +0530 (Fri, 22 Feb 2013)" );
	script_cve_id( "CVE-2013-0783", "CVE-2013-0784", "CVE-2013-0772", "CVE-2013-0765", "CVE-2013-0773", "CVE-2013-0774", "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0777", "CVE-2013-0778", "CVE-2013-0779", "CVE-2013-0780", "CVE-2013-0781", "CVE-2013-0782" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1729-1" );
	script_name( "Ubuntu Update for firefox USN-1729-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS|12\\.10)" );
	script_tag( name: "affected", value: "firefox on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Olli Pettay, Christoph Diehl, Gary Kwong, Jesse Ruderman, Andrew McCreight,
  Joe Drew, Wayne Mery, Alon Zakai, Christian Holler, Gary Kwong, Luke
  Wagner, Terrence Cole, Timothy Nikkel, Bill McCloskey, and Nicolas Pierron
  discovered multiple memory safety issues affecting Firefox. If the user
  were tricked into opening a specially crafted page, an attacker could
  possibly exploit these to cause a denial of service via application crash.
  (CVE-2013-0783, CVE-2013-0784)

  Atte Kettunen discovered that Firefox could perform an out-of-bounds read
  while rendering GIF format images. An attacker could exploit this to crash
  Firefox. (CVE-2013-0772)

  Boris Zbarsky discovered that Firefox did not properly handle some wrapped
  WebIDL objects. If the user were tricked into opening a specially crafted
  page, an attacker could possibly exploit this to cause a denial of service
  via application crash, or potentially execute code with the privileges of
  the user invoking Firefox. (CVE-2013-0765)

  Bobby Holley discovered vulnerabilities in Chrome Object Wrappers (COW) and
  System Only Wrappers (SOW). If a user were tricked into opening a specially
  crafted page, a remote attacker could exploit this to bypass security
  protections to obtain sensitive information or potentially execute code
  with the privileges of the user invoking Firefox. (CVE-2013-0773)

  Frederik Braun that Firefox made the location of the active browser profile
  available to JavaScript workers. (CVE-2013-0774)

  A use-after-free vulnerability was discovered in Firefox. An attacker could
  potentially exploit this to execute code with the privileges of the user
  invoking Firefox. (CVE-2013-0775)

  Michal Zalewski discovered that Firefox would not always show the correct
  address when cancelling a proxy authentication prompt. A remote attacker
  could exploit this to conduct URL spoofing and phishing attacks.
  (CVE-2013-0776)

  Abhishek Arya discovered several problems related to memory handling. If
  the user were tricked into opening a specially crafted page, an attacker
  could possibly exploit these to cause a denial of service via application
  crash, or potentially execute code with the privileges of the user invoking
  Firefox. (CVE-2013-0777, CVE-2013-0778, CVE-2013-0779, CVE-2013-0780,
  CVE-2013-0781, CVE-2013-0782)" );
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
	if(( res = isdpkgvuln( pkg: "firefox", ver: "19.0+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "19.0+build1-0ubuntu0.11.10.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "19.0+build1-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "19.0+build1-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

