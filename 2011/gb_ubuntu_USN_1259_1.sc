if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1259-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840798" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-11 09:55:23 +0530 (Fri, 11 Nov 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_xref( name: "USN", value: "1259-1" );
	script_cve_id( "CVE-2011-3368", "CVE-2011-3348", "CVE-2011-1176" );
	script_name( "Ubuntu Update for apache2 USN-1259-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1259-1" );
	script_tag( name: "affected", value: "apache2 on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that the mod_proxy module in Apache did not properly
  interact with the RewriteRule and ProxyPassMatch pattern matches
  in the configuration of a reverse proxy. This could allow remote
  attackers to contact internal webservers behind the proxy that were
  not intended for external exposure. (CVE-2011-3368)

  Stefano Nichele discovered that the mod_proxy_ajp module in Apache when
  used with mod_proxy_balancer in certain configurations could allow
  remote attackers to cause a denial of service via a malformed HTTP
  request. (CVE-2011-3348)

  Samuel Montosa discovered that the ITK Multi-Processing Module for
  Apache did not properly handle certain configuration sections that
  specify NiceValue but not AssignUserID, preventing Apache from dropping
  privileges correctly. This issue only affected Ubuntu 10.04 LTS, Ubuntu
  10.10 and Ubuntu 11.04. (CVE-2011-1176)

  USN 1199-1 fixed a vulnerability in the byterange filter of Apache. The
  upstream patch introduced a regression in Apache when handling specific
  byte range requests. This update fixes the issue.

  Original advisory details:

  A flaw was discovered in the byterange filter in Apache. A remote attacker
  could exploit this to cause a denial of service via resource exhaustion." );
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
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "apache2-mpm-itk", ver: "2.2.16-1ubuntu3.4", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.2.16-1ubuntu3.4", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "apache2-mpm-itk", ver: "2.2.14-5ubuntu8.7", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.2.14-5ubuntu8.7", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "apache2-mpm-itk", ver: "2.2.17-1ubuntu1.4", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.2.17-1ubuntu1.4", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "apache2.2-common", ver: "2.2.8-1ubuntu0.22", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

