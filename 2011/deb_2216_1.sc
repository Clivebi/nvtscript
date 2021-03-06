if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69560" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0997" );
	script_name( "Debian Security Advisory DSA 2216-1 (isc-dhcp)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202216-1" );
	script_tag( name: "insight", value: "Sebastian Krahmer and Marius Tomaschewski discovered that dhclient of
isc-dhcp, a DHCP client, is not properly filtering shell meta-characters
in certain options in DHCP server responses.  These options are reused in
an insecure fashion by dhclient scripts.  This allows an attacker to execute
arbitrary commands with the privileges of such a process by sending crafted
DHCP options to a client using a rogue server.


For the oldstable distribution (lenny), this problem has been fixed in
additional update for dhcp3.

For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze2.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 4.1.1-P1-16.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your isc-dhcp packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to isc-dhcp
announced via advisory DSA 2216-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dhcp3-client", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-common", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-dev", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-relay", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-server", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-dbg", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-udeb", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-common", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-dev", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay-dbg", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-dbg", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.1.1-P1-15+squeeze2", rls: "DEB6" ) ) != NULL){
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

