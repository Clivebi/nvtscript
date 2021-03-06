if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1100-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840624" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-04-01 15:34:04 +0200 (Fri, 01 Apr 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1100-1" );
	script_cve_id( "CVE-2011-1024", "CVE-2011-1025", "CVE-2011-1081" );
	script_name( "Ubuntu Update for openldap, openldap2.3 vulnerabilities USN-1100-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(9\\.10|10\\.10|10\\.04 LTS|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1100-1" );
	script_tag( name: "affected", value: "openldap, openldap2.3 vulnerabilities on Ubuntu 8.04 LTS,
  Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that OpenLDAP did not properly check forwarded
  authentication failures when using a slave server and chain overlay. If
  OpenLDAP were configured in this manner, an attacker could bypass
  authentication checks by sending an invalid password to a slave server.
  (CVE-2011-1024)

  It was discovered that OpenLDAP did not properly perform authentication
  checks to the rootdn when using the back-ndb backend. An attacker could
  exploit this to access the directory by sending an arbitrary password.
  Ubuntu does not ship OpenLDAP with back-ndb support by default. This issue
  did not affect Ubuntu 8.04 LTS. (CVE-2011-1025)

  It was discovered that OpenLDAP did not properly validate modrdn requests.
  An unauthenticated remote user could use this to cause a denial of service
  via application crash. (CVE-2011-1081)" );
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
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "ldap-utils", ver: "2.4.18-0ubuntu1.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap-2.4-2-dbg", ver: "2.4.18-0ubuntu1.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap-2.4-2", ver: "2.4.18-0ubuntu1.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap2-dev", ver: "2.4.18-0ubuntu1.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "slapd-dbg", ver: "2.4.18-0ubuntu1.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "slapd", ver: "2.4.18-0ubuntu1.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "ldap-utils", ver: "2.4.23-0ubuntu3.5", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap-2.4-2-dbg", ver: "2.4.23-0ubuntu3.5", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap-2.4-2", ver: "2.4.23-0ubuntu3.5", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap2-dev", ver: "2.4.23-0ubuntu3.5", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "slapd-dbg", ver: "2.4.23-0ubuntu3.5", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "slapd", ver: "2.4.23-0ubuntu3.5", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ldap-utils", ver: "2.4.21-0ubuntu5.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap-2.4-2-dbg", ver: "2.4.21-0ubuntu5.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap-2.4-2", ver: "2.4.21-0ubuntu5.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap2-dev", ver: "2.4.21-0ubuntu5.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "slapd-dbg", ver: "2.4.21-0ubuntu5.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "slapd", ver: "2.4.21-0ubuntu5.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ldap-utils", ver: "2.4.9-0ubuntu0.8.04.5", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap-2.4-2-dbg", ver: "2.4.9-0ubuntu0.8.04.5", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap-2.4-2", ver: "2.4.9-0ubuntu0.8.04.5", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libldap2-dev", ver: "2.4.9-0ubuntu0.8.04.5", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "slapd-dbg", ver: "2.4.9-0ubuntu0.8.04.5", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "slapd", ver: "2.4.9-0ubuntu0.8.04.5", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

