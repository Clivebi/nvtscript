if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71822" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-3461" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:32:41 -0400 (Thu, 30 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2526-1 (libotr)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202526-1" );
	script_tag( name: "insight", value: "Just Ferguson discovered that libotr, an off-the-record (OTR) messaging
library, can be forced to perform zero-length allocations for heap buffers
that are used in base64 decoding routines.  An attacker can exploit this
flaw by sending crafted messages to an application that is using libotr to
perform denial of service attacks or potentially execute arbitrary code.

For the stable distribution (squeeze), this problem has been fixed in
version 3.2.0-2+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 3.2.1-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.2.1-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libotr packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libotr
announced via advisory DSA 2526-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libotr2", ver: "3.2.0-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libotr2-bin", ver: "3.2.0-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libotr2-dev", ver: "3.2.0-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libotr2", ver: "3.2.1-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libotr2-bin", ver: "3.2.1-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libotr2-dev", ver: "3.2.1-1", rls: "DEB7" ) ) != NULL){
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

