if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69339" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Debian Security Advisory DSA 2203-1 (nss)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202203-1" );
	script_tag( name: "insight", value: "This update for the Network Security Service libraries marks several
fraudulent HTTPS certificates as unstrusted.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.12.3.1-0lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 3.12.8-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 3.12.9.with.ckbi.1.82-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your nss packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to nss
announced via advisory DSA 2203-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "3.12.3.1-0lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d-dbg", ver: "3.12.3.1-0lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dev", ver: "3.12.3.1-0lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-tools", ver: "3.12.3.1-0lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "3.12.8-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d-dbg", ver: "3.12.8-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dev", ver: "3.12.8-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-tools", ver: "3.12.8-1+squeeze1", rls: "DEB6" ) ) != NULL){
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
