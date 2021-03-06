if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69119" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2011-0413" );
	script_name( "Debian Security Advisory DSA 2184-1 (isc-dhcp)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "insight", value: "It was discovered that the ISC DHCPv6 server does not correctly
process requests which come from unexpected source addresses, leading
to an assertion failure and a daemon crash." );
	script_tag( name: "summary", value: "The remote host is missing an update to isc-dhcp
announced via advisory DSA 2184-1." );
	script_tag( name: "solution", value: "The oldstable distribution (lenny) is not affected by this problem.

For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 4.1.1-P1-16.

  We recommend that you upgrade your isc-dhcp packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202184-1" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dhcp3-client", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-common", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-dev", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-relay", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-server", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-dbg", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-udeb", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-common", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-dev", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay-dbg", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-dbg", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.1.1-P1-15+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-client", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-common", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-dev", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-relay", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-server", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-dbg", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-udeb", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-common", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-dev", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay-dbg", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-dbg", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.1.1-P1-16", rls: "DEB7" ) ) != NULL){
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

