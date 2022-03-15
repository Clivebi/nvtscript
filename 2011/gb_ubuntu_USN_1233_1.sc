if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1233-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840781" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)" );
	script_xref( name: "USN", value: "1233-1" );
	script_cve_id( "CVE-2011-1527", "CVE-2011-1528", "CVE-2011-1529" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Ubuntu Update for krb5 USN-1233-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1233-1" );
	script_tag( name: "affected", value: "krb5 on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Nalin Dahyabhai, Andrej Ota and Kyle Moffett discovered a NULL
  pointer dereference in the KDC LDAP backend. An unauthenticated
  remote attacker could use this to cause a denial of service. This
  issue affected Ubuntu 11.10. (CVE-2011-1527)

  Mark Deneen discovered that an assert() could be triggered in the
  krb5_ldap_lockout_audit() function in the KDC LDAP backend and
  the krb5_db2_lockout_audit() function in the KDC DB2 backend. An
  unauthenticated remote attacker could use this to cause a denial of
  service. (CVE-2011-1528)

  It was discovered that a NULL pointer dereference could occur in the
  lookup_lockout_policy() function in the KDC LDAP and DB2 backends.
  An unauthenticated remote attacker could use this to cause a denial of
  service. (CVE-2011-1529)" );
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
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.8.1+dfsg-5ubuntu0.8", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.8.1+dfsg-5ubuntu0.8", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.8.1+dfsg-2ubuntu0.10", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.8.1+dfsg-2ubuntu0.10", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.8.3+dfsg-5ubuntu2.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.8.3+dfsg-5ubuntu2.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

