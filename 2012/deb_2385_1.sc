if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70704" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-0206" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:27:26 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2385-1 (pdns)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202385-1" );
	script_tag( name: "insight", value: "Ray Morris discovered that the PowerDNS authoritative sever responds
to response packets.  An attacker who can spoof the source address of
IP packets can cause an endless packet loop between a PowerDNS
authoritative server and another DNS server, leading to a denial of
service.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.9.21.2-1+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 2.9.22-8+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your pdns packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to pdns
announced via advisory DSA 2385-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "pdns-backend-geo", ver: "2.9.21.2-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-ldap", ver: "2.9.21.2-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-mysql", ver: "2.9.21.2-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-pgsql", ver: "2.9.21.2-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-pipe", ver: "2.9.21.2-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-sqlite", ver: "2.9.21.2-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-sqlite3", ver: "2.9.21.2-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-doc", ver: "2.9.21.2-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-server", ver: "2.9.21.2-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-geo", ver: "2.9.22-8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-ldap", ver: "2.9.22-8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-mysql", ver: "2.9.22-8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-pgsql", ver: "2.9.22-8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-pipe", ver: "2.9.22-8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-sqlite", ver: "2.9.22-8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-sqlite3", ver: "2.9.22-8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-doc", ver: "2.9.22-8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-server", ver: "2.9.22-8+squeeze1", rls: "DEB6" ) ) != NULL){
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

