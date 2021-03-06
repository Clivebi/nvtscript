if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71143" );
	script_cve_id( "CVE-2012-0841" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:31:39 -0400 (Mon, 12 Mar 2012)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Debian Security Advisory DSA 2417-1 (libxml2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202417-1" );
	script_tag( name: "insight", value: "It was discovered that the internal hashing routine of libxml2,
a library providing an extensive API to handle XML data, is vulnerable to
predictable hash collisions.  Given an attacker with knowledge of the
hashing algorithm, it is possible to craft input that creates a large
amount of collisions.  As a result it is possible to perform denial of
service attacks against applications using libxml2 functionality because
of the computational overhead.


For the stable distribution (squeeze), this problem has been fixed in
version 2.7.8.dfsg-2+squeeze3.

For the testing (wheezy) and unstable (sid) distributions, this problem
will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libxml2 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libxml2
announced via advisory DSA 2417-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.7.8.dfsg-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.7.8.dfsg-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.7.8.dfsg-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.7.8.dfsg-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.7.8.dfsg-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.7.8.dfsg-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.7.8.dfsg-2+squeeze3", rls: "DEB6" ) ) != NULL){
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

