if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72628" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-5134" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-12-04 11:43:12 -0500 (Tue, 04 Dec 2012)" );
	script_name( "Debian Security Advisory DSA 2580-1 (libxml2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202580-1" );
	script_tag( name: "insight", value: "Jueri Aedla discovered a buffer overflow in the libxml XML library, which
could result in the execution of arbitrary code.

For the stable distribution (squeeze), this problem has been fixed in
version 2.7.8.dfsg-2+squeeze6.

For the unstable distribution (sid), this problem has been fixed in
version 2.8.0+dfsg1-7." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libxml2 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libxml2
announced via advisory DSA 2580-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.7.8.dfsg-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.7.8.dfsg-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.7.8.dfsg-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.7.8.dfsg-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.7.8.dfsg-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.7.8.dfsg-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.7.8.dfsg-2+squeeze6", rls: "DEB6" ) ) != NULL){
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

