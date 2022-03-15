if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69105" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0495" );
	script_name( "Debian Security Advisory DSA 2171-1 (asterisk)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_tag( name: "insight", value: "Matthew Nicholson discovered a buffer overflow in the SIP channel driver
of Asterisk, an open source PBX and telephony toolkit, which could lead
to the execution of arbitrary code." );
	script_tag( name: "summary", value: "The remote host is missing an update to asterisk
announced via advisory DSA 2171-1." );
	script_tag( name: "solution", value: "For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.21.2~dfsg-3+lenny2.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.2.9-2+squeeze1.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your asterisk packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202171-1" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1.4.21.2~dfsg-3+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1.4.21.2~dfsg-3+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1.4.21.2~dfsg-3+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1.4.21.2~dfsg-3+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1.4.21.2~dfsg-3+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-h323", ver: "1.4.21.2~dfsg-3+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-sounds-main", ver: "1.4.21.2~dfsg-3+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1.6.2.9-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1.6.2.9-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1.6.2.9-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1.6.2.9-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1.6.2.9-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-h323", ver: "1.6.2.9-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-sounds-main", ver: "1.6.2.9-2+squeeze1", rls: "DEB6" ) ) != NULL){
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

