if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72416" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2012-3955" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-26 11:19:41 -0400 (Wed, 26 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2551-1 (isc-dhcp)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202551-1" );
	script_tag( name: "insight", value: "Glen Eustace discovered that the ISC DHCP server, a server for automatic
IP address assignment, is not properly handling changes in the expiration
times of a lease.  An attacker may use this flaw to crash the service
and cause denial of service conditions, by reducing the expiration time
of an active IPv6 lease.

For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze8.

For the testing distribution (wheezy), this problem has will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 4.2.4-2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your isc-dhcp packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to isc-dhcp
announced via advisory DSA 2551-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dhcp3-client", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-common", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-dev", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-relay", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-server", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-dbg", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-udeb", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-common", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-dev", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay-dbg", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-dbg", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.1.1-P1-15+squeeze8", rls: "DEB6" ) ) != NULL){
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

