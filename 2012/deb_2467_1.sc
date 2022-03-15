if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71346" );
	script_cve_id( "CVE-2012-2351" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:44:15 -0400 (Thu, 31 May 2012)" );
	script_name( "Debian Security Advisory DSA 2467-1 (mahara)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202467-1" );
	script_tag( name: "insight", value: "It was discovered that Mahara, the portfolio, weblog, and resume builder,
had an insecure default with regards to SAML-based authentication used
with more than one SAML identity provider. Someone with control over one
IdP could impersonate users from other IdP's.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.6-2+squeeze4.

For the testing distribution (wheezy) and unstable distribution (sid),
this problem has been fixed in version 1.4.2-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your mahara packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to mahara
announced via advisory DSA 2467-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mahara", ver: "1.2.6-2+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mahara-apache2", ver: "1.2.6-2+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mahara-mediaplayer", ver: "1.2.6-2+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mahara", ver: "1.4.2-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mahara-apache2", ver: "1.4.2-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mahara-mediaplayer", ver: "1.4.2-1", rls: "DEB7" ) ) != NULL){
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

