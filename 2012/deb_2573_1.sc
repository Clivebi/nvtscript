if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72568" );
	script_cve_id( "CVE-2012-4523", "CVE-2012-4566" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-16 03:15:41 -0500 (Fri, 16 Nov 2012)" );
	script_name( "Debian Security Advisory DSA 2573-1 (radsecproxy)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202573-1" );
	script_tag( name: "insight", value: "Ralf Paffrath reported that Radsecproxy, a RADIUS protocol proxy, mixed up
pre- and post-handshake verification of clients. This vulnerability may
wrongly accept clients without checking their certificate chain under
certain configurations.

Raphael Geissert spotted that the fix for CVE-2012-4523 was incomplete,
giving origin to CVE-2012-4566. Both vulnerabilities are fixed with this
update.

Notice that this fix may make Radsecproxy reject some clients that are
currently (erroneously) being accepted.

For the stable distribution (squeeze), these problems have been fixed in
version 1.4-1+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in
version 1.6.2-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.6.2-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your radsecproxy packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to radsecproxy
announced via advisory DSA 2573-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "radsecproxy", ver: "1.4-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "radsecproxy", ver: "1.6.2-1", rls: "DEB7" ) ) != NULL){
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

