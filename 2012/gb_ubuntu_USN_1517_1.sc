if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1517-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841093" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-26 11:10:18 +0530 (Thu, 26 Jul 2012)" );
	script_cve_id( "CVE-2012-3382", "CVE-2010-1459" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "USN", value: "1517-1" );
	script_name( "Ubuntu Update for mono USN-1517-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1517-1" );
	script_tag( name: "affected", value: "mono on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that the Mono System.Web library incorrectly filtered
  certain error messages related to forbidden files. If a user were tricked
  into opening a specially crafted URL, an attacker could possibly exploit
  this to conduct cross-site scripting (XSS) attacks. (CVE-2012-3382)

  It was discovered that the Mono System.Web library incorrectly handled the
  EnableViewStateMac property. If a user were tricked into opening a
  specially crafted URL, an attacker could possibly exploit this to conduct
  cross-site scripting (XSS) attacks. This issue only affected Ubuntu
  10.04 LTS. (CVE-2010-1459)" );
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
	if(( res = isdpkgvuln( pkg: "libmono-system-web1.0-cil", ver: "2.4.4~svn151842-1ubuntu4.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libmono-system-web2.0-cil", ver: "2.4.4~svn151842-1ubuntu4.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libmono-system-web2.0-cil", ver: "2.10.8.1-1ubuntu2.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libmono-system-web4.0-cil", ver: "2.10.8.1-1ubuntu2.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "libmono-system-web2.0-cil", ver: "2.10.5-1ubuntu0.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libmono-system-web4.0-cil", ver: "2.10.5-1ubuntu0.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libmono-system-web1.0-cil", ver: "2.6.7-5ubuntu3.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libmono-system-web2.0-cil", ver: "2.6.7-5ubuntu3.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

