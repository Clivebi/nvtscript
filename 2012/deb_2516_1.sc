if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71493" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2012-3571", "CVE-2012-3954" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:14:04 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2516-1 (isc-dhcp)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202516-1" );
	script_tag( name: "insight", value: "Two security vulnerabilities affecting ISC dhcpd, a server for automatic
IP address assignment, in Debian have been discovered.

CVE-2012-3571

Markus Hietava of the Codenomicon CROSS project discovered that it is
possible to force the server to enter an infinite loop via messages with
malformed client identifiers.

CVE-2012-3954

Glen Eustace discovered that DHCP servers running in DHCPv6 mode
and possibly DHCPv4 mode suffer of memory leaks while processing messages.
An attacker can use this flaw to exhaust resources and perform denial
of service attacks.


For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze4.

For the testing (wheezy) and unstable (sid) distributions, this problem
will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your isc-dhcp packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to isc-dhcp
announced via advisory DSA 2516-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dhcp3-client", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-common", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-dev", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-relay", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-server", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-dbg", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-udeb", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-common", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-dev", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay-dbg", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-dbg", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.1.1-P1-15+squeeze6", rls: "DEB6" ) ) != NULL){
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

