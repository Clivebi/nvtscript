if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70689" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2011-4528", "CVE-2011-4869" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:15:52 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2370-1 (unbound)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202370-1" );
	script_tag( name: "insight", value: "It was discovered that Unbound, a recursive DNS resolver, would crash
when processing certain malformed DNS responses from authoritative DNS
servers, leading to denial of service.

CVE-2011-4528
Unbound attempts to free unallocated memory during processing
of duplicate CNAME records in a signed zone.

CVE-2011-4869
Unbound does not properly process malformed responses which
lack expected NSEC3 records.

For the oldstable distribution (lenny), these problems have been fixed in
version 1.4.6-1~lenny2.

For the stable distribution (squeeze), these problems have been fixed in
version 1.4.6-1+squeeze2.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 1.4.14-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your unbound packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to unbound
announced via advisory DSA 2370-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libunbound-dev", ver: "1.4.6-1~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libunbound2", ver: "1.4.6-1~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "unbound", ver: "1.4.6-1~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "unbound-host", ver: "1.4.6-1~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libunbound-dev", ver: "1.4.6-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libunbound2", ver: "1.4.6-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "unbound", ver: "1.4.6-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "unbound-host", ver: "1.4.6-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libunbound-dev", ver: "1.4.14-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libunbound2", ver: "1.4.14-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-unbound", ver: "1.4.14-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "unbound", ver: "1.4.14-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "unbound-anchor", ver: "1.4.14-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "unbound-host", ver: "1.4.14-2", rls: "DEB7" ) ) != NULL){
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

