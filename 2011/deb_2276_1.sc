if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69982" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_cve_id( "CVE-2011-2529", "CVE-2011-2535" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Debian Security Advisory DSA 2276-1 (asterisk)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202276-1" );
	script_tag( name: "insight", value: "Paul Belanger reported a vulnerability in Asterisk identified as AST-2011-008
(CVE-2011-2529) through which an unauthenticated attacker may crash an Asterisk
server remotely. A package containing a null char causes the SIP header parser
to alter unrelated memory structures.

Jared Mauch reported a vulnerability in Asterisk identified as AST-2011-009
through which an unauthenticated attacker may crash an Asterisk server remotely.
If a user sends a package with a Contact header with a missing left angle
bracket (<) the server will crash. A possible workaround is to disable chan_sip.

The vulnerability identified as AST-2011-010 (CVE-2011-2535) reported about an
input validation error in the IAX2 channel driver. An unauthenticated attacker
may crash an Asterisk server remotely by sending a crafted option control frame.


For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.21.2~dfsg-3+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.2.9-2+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in
version 1:1.8.4.3-1.

For the unstable distribution (sid), this problem has been fixed in
version 1:1.8.4.3-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your asterisk packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to asterisk
announced via advisory DSA 2276-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1:1.4.21.2~dfsg-3+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:1.4.21.2~dfsg-3+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:1.4.21.2~dfsg-3+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:1.4.21.2~dfsg-3+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:1.4.21.2~dfsg-3+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-h323", ver: "1:1.4.21.2~dfsg-3+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-sounds-main", ver: "1:1.4.21.2~dfsg-3+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1:1.6.2.9-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:1.6.2.9-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:1.6.2.9-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:1.6.2.9-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:1.6.2.9-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-h323", ver: "1:1.6.2.9-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-sounds-main", ver: "1:1.6.2.9-2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dahdi", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-h323", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-mobile", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-modules", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-mp3", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-mysql", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-ooh323", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-voicemail", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-voicemail-imapstorage", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-voicemail-odbcstorage", ver: "1:1.8.4.4~dfsg-2", rls: "DEB7" ) ) != NULL){
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

