if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72472" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2893" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-13 02:34:19 -0400 (Sat, 13 Oct 2012)" );
	script_name( "Debian Security Advisory DSA 2555-1 (libxslt)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202555-1" );
	script_tag( name: "insight", value: "Nicholas Gregoire and Cris Neckar discovered several memory handling
bugs in libxslt, which could lead to denial of service or the execution
of arbitrary code if a malformed document is processed.

For the stable distribution (squeeze), these problems have been fixed in
version 1.1.26-6+squeeze2.

For the unstable distribution (sid), these problems have been fixed in
version 1.1.26-14." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libxslt packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libxslt
announced via advisory DSA 2555-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxslt1-dbg", ver: "1.1.26-6+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1-dev", ver: "1.1.26-6+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1.1", ver: "1.1.26-6+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxslt1", ver: "1.1.26-6+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxslt1-dbg", ver: "1.1.26-6+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xsltproc", ver: "1.1.26-6+squeeze2", rls: "DEB6" ) ) != NULL){
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

