if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1520-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841097" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-03 11:17:37 +0530 (Fri, 03 Aug 2012)" );
	script_cve_id( "CVE-2012-1015", "CVE-2012-1014", "CVE-2012-1013", "CVE-2012-1012" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1520-1" );
	script_name( "Ubuntu Update for krb5 USN-1520-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1520-1" );
	script_tag( name: "affected", value: "krb5 on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Emmanuel Bouillon discovered that the MIT krb5 Key Distribution Center
  (KDC) daemon could free an uninitialized pointer when handling a
  malformed AS-REQ message. A remote unauthenticated attacker could
  use this to cause a denial of service or possibly execute arbitrary
  code. (CVE-2012-1015)

  Emmanuel Bouillon discovered that the MIT krb5 Key Distribution Center
  (KDC) daemon could dereference an uninitialized pointer while handling
  a malformed AS-REQ message. A remote unauthenticated attacker could
  use this to cause a denial of service or possibly execute arbitrary
  code. This issue only affected Ubuntu 12.04 LTS. (CVE-2012-1014)

  Simo Sorce discovered that the MIT krb5 Key Distribution Center (KDC)
  daemon could dereference a NULL pointer when handling a malformed
  TGS-REQ message. A remote authenticated attacker could use this to
  cause a denial of service. (CVE-2012-1013)

  It was discovered that the kadmin protocol implementation in MIT krb5
  did not properly restrict access to the SET_STRING and GET_STRINGS
  operations. A remote authenticated attacker could use this to expose
  or modify sensitive information. This issue only affected Ubuntu
  12.04 LTS. (CVE-2012-1012)" );
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
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.8.1+dfsg-2ubuntu0.11", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.8.1+dfsg-2ubuntu0.11", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.8.1+dfsg-2ubuntu0.11", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.10+dfsg~beta1-2ubuntu0.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.10+dfsg~beta1-2ubuntu0.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.10+dfsg~beta1-2ubuntu0.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.9.1+dfsg-1ubuntu2.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.9.1+dfsg-1ubuntu2.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.9.1+dfsg-1ubuntu2.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.8.3+dfsg-5ubuntu2.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.8.3+dfsg-5ubuntu2.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.8.3+dfsg-5ubuntu2.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

