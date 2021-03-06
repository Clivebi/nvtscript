if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72175" );
	script_cve_id( "CVE-2012-3547" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-15 04:24:30 -0400 (Sat, 15 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2546-1 (freeradius)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202546-1" );
	script_tag( name: "insight", value: "Timo Warns discovered that the EAP-TLS handling of freeradius, a
high-performance and highly configurable RADIUS server, is not properly
performing length checks on user-supplied input before copying to a local
stack buffer.  As a result, an unauthenticated attacker can exploit this
flaw to crash the daemon or execute arbitrary code via crafted
certificates.

For the stable distribution (squeeze), this problem has been fixed in
version 2.1.10+dfsg-2+squeeze1.

For the testing distribution (wheezy), this problem has will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2.1.12+dfsg-1.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your freeradius packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to freeradius
announced via advisory DSA 2546-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "freeradius", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-common", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-dbg", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-dialupadmin", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-iodbc", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-krb5", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-ldap", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-mysql", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-postgresql", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "freeradius-utils", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeradius-dev", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeradius2", ver: "2.1.10+dfsg-2+squeeze1", rls: "DEB6" ) ) != NULL){
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

