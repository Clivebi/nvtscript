if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703356" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-6908" );
	script_name( "Debian Security Advisory DSA 3356-1 (openldap - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-09-12 00:00:00 +0200 (Sat, 12 Sep 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3356.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openldap on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 2.4.31-2+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 2.4.40+dfsg-1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 2.4.42+dfsg-2.

We recommend that you upgrade your openldap packages." );
	script_tag( name: "summary", value: "Denis Andzakovic discovered that
OpenLDAP, a free implementation of the Lightweight Directory Access Protocol,
does not properly handle BER data. An unauthenticated remote attacker can use this
flaw to cause a denial of service (slapd daemon crash) via a specially crafted
packet." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ldap-utils", ver: "2.4.31-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldap-2.4-2:amd64", ver: "2.4.31-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldap-2.4-2:i386", ver: "2.4.31-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldap-2.4-2-dbg:amd64", ver: "2.4.31-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldap-2.4-2-dbg:i386", ver: "2.4.31-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldap2-dev:amd64", ver: "2.4.31-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldap2-dev:i386", ver: "2.4.31-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "slapd", ver: "2.4.31-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "slapd-dbg", ver: "2.4.31-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "slapd-smbk5pwd", ver: "2.4.31-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

