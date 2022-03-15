if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71155" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2011-2748", "CVE-2011-2749" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:33:55 -0400 (Mon, 12 Mar 2012)" );
	script_name( "Debian Security Advisory DSA 2292-1 (isc-dhcp)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202292-1" );
	script_tag( name: "insight", value: "David Zych discovered that the ISC DHCP crashes when processing
certain packets, leading to a denial of service.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.1.1-6+lenny6 of the dhcp3 package.

For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze3 of the isc-dhcp package.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your ISC DHCP packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to isc-dhcp
announced via advisory DSA 2292-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dhcp3-client", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-common", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-dev", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-relay", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dhcp3-server", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-dbg", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-client-udeb", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-common", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-dev", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-relay-dbg", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-dbg", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "isc-dhcp-server-ldap", ver: "4.1.1-P1-15+squeeze3", rls: "DEB6" ) ) != NULL){
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

