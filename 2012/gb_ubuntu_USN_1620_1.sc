if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1620-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841200" );
	script_version( "2020-08-17T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 08:01:28 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-10-29 11:03:49 +0530 (Mon, 29 Oct 2012)" );
	script_cve_id( "CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "USN", value: "1620-1" );
	script_name( "Ubuntu Update for firefox USN-1620-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1620-1" );
	script_tag( name: "affected", value: "firefox on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Mariusz Mlynski and others discovered several flaws in Firefox that allowed
  a remote attacker to conduct cross-site scripting (XSS) attacks.
  (CVE-2012-4194, CVE-2012-4195)

  Antoine Delignat-Lavaud discovered a flaw in the way Firefox handled the
  Location object. If a user were tricked into opening a specially crafted
  page, a remote attacker could exploit this to bypass security protections
  and perform cross-origin reading of the Location object. (CVE-2012-4196)" );
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
	if(( res = isdpkgvuln( pkg: "firefox", ver: "16.0.2+build1-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "16.0.2+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "16.0.2+build1-0ubuntu0.11.10.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "16.0.2+build1-0ubuntu0.11.04.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

