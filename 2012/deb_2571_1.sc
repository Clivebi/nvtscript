if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72566" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-4505" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-16 03:15:03 -0500 (Fri, 16 Nov 2012)" );
	script_name( "Debian Security Advisory DSA 2571-1 (libproxy)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202571-1" );
	script_tag( name: "insight", value: "The Red Hat Security Response Team discovered that libproxy, a library
for automatic proxy configuration management, applied insufficient
validation to the Content-Length header sent by a server providing a
proxy.pac file. Such remote server could trigger an integer overflow
and consequently overflow an in-memory buffer.

For the stable distribution (squeeze), this problem has been fixed in
version 0.3.1-2+squeeze1.

For the testing distribution (wheezy), and the unstable distribution
(sid), this problem has been fixed in version 0.3.1-5.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libproxy packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libproxy
announced via advisory DSA 2571-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libproxy-dev", ver: "0.3.1-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libproxy-tools", ver: "0.3.1-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libproxy0", ver: "0.3.1-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libproxy", ver: "0.3.1-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libproxy-dev", ver: "0.3.1-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libproxy-tools", ver: "0.3.1-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libproxy0", ver: "0.3.1-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libproxy", ver: "0.3.1-5.1", rls: "DEB7" ) ) != NULL){
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

