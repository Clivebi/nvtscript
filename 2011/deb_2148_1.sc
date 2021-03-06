if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68986" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0427" );
	script_name( "Debian Security Advisory DSA 2148-1 (tor)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202148-1" );
	script_tag( name: "insight", value: "The developers of Tor, an anonymizing overlay network for TCP, found
three security issues during a security audit. A heap overflow allowed
the execution of arbitrary code (CVE-2011-0427), a denial of service
vulnerability was found in the zlib compression handling and some key
memory was incorrectly zeroed out before being freed. The latter two
issues do not yet have CVE identifiers assigned.

For the stable distribution (lenny), this problem has been fixed in
version 0.2.1.29-1~lenny+1.

For the testing distribution (squeeze) and the unstable distribution (sid),
this problem has been fixed in version 0.2.1.29-1.

For the experimental distribution, this problem has been fixed in
version 0.2.2.21-alpha-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your tor packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to tor
announced via advisory DSA 2148-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "tor", ver: "0.2.1.29-1~lenny+1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor-dbg", ver: "0.2.1.29-1~lenny+1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor-geoipdb", ver: "0.2.1.29-1~lenny+1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor", ver: "0.2.1.29-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor-dbg", ver: "0.2.1.29-1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tor-geoipdb", ver: "0.2.1.29-1", rls: "DEB6" ) ) != NULL){
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

