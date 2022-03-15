if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72170" );
	script_cve_id( "CVE-2012-3458" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-15 04:23:55 -0400 (Sat, 15 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2541-1 (beaker)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202541-1" );
	script_tag( name: "insight", value: "It was discovered that Beaker, a cache and session library for Python,
when using the python-crypto backend, is vulnerable to information
disclosure due to a cryptographic weakness related to the use of the
AES cipher in ECB mode.

Systems that have the python-pycryptopp package should not be
vulnerable, as this backend is preferred over python-crypto.

After applying this update, existing sessions will be invalidated.

For the stable distribution (squeeze), this problem has been fixed in
version 1.5.4-4+squeeze1.

For the testing distribution (wheezy), and the unstable distribution
(sid), this problem has been fixed in version 1.6.3-1.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your beaker packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to beaker
announced via advisory DSA 2541-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-beaker", ver: "1.5.4-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-beaker", ver: "1.5.4-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-beaker", ver: "1.6.3-1.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-beaker", ver: "1.6.3-1.1", rls: "DEB7" ) ) != NULL){
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

