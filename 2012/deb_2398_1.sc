if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70715" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3389", "CVE-2012-0036" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-12 06:35:15 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2398-1 (curl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202398-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in Curl, an URL transfer
library. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2011-3389

This update enables OpenSSL workarounds against the BEAST attack.

CVE-2012-0036

Dan Fandrich discovered that Curl performs insufficient sanitising
when extracting the file path part of an URL.

For the oldstable distribution (lenny), this problem has been fixed in
version 7.18.2-8lenny6.

For the stable distribution (squeeze), this problem has been fixed in
version 7.21.0-2.1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 7.24.0-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your curl packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to curl
announced via advisory DSA 2398-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "curl", ver: "7.18.2-8lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.18.2-8lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.18.2-8lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.18.2-8lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.18.2-8lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.18.2-8lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "curl", ver: "7.21.0-2.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.21.0-2.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.21.0-2.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.21.0-2.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.21.0-2.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.21.0-2.1+squeeze1", rls: "DEB6" ) ) != NULL){
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

