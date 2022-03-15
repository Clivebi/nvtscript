if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71249" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2011-3389" );
	script_version( "2020-10-27T15:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-04-30 07:55:40 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Debian Security Advisory DSA 2398-2 (curl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202398-2" );
	script_tag( name: "insight", value: "cURL is a command-line tool and library for transferring data with URL
syntax.  It was discovered that the countermeasures against the
Dai/Rogaway chosen-plaintext attack on SSL/TLS (CVE-2011-3389,
BEAST) cause interoperability issues with some server
implementations.  This update ads the CURLOPT_SSL_OPTIONS and
CURLSSLOPT_ALLOW_BEAST options to the library, and the

  - --ssl-allow-beast option to the curl program.

For the stable distribution (squeeze), this problem has been fixed in
version 7.21.0-2.1+squeeze2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your curl packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to curl
announced via advisory DSA 2398-2." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "curl", ver: "7.21.0-2.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.21.0-2.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.21.0-2.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.21.0-2.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.21.0-2.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.21.0-2.1+squeeze2", rls: "DEB6" ) ) != NULL){
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

