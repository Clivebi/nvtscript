if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72408" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-2186", "CVE-2012-3812", "CVE-2012-3863", "CVE-2012-4737" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-23 02:15:34 -0400 (Sun, 23 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2550-1 (asterisk)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202550-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in Asterisk, a PBX and telephony
toolkit, allowing privilege escalation in the Asterisk Manager, denial of
service or privilege escalation.

For the stable distribution (squeeze), these problems have been fixed in
version 1:1.6.2.9-2+squeeze7.

For the testing distribution (wheezy) and the unstable distribution (sid),
these problems have been fixed in version 1:1.8.13.1~dfsg-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your asterisk packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to asterisk
announced via advisory DSA 2550-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1:1.6.2.9-2+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:1.6.2.9-2+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:1.6.2.9-2+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:1.6.2.9-2+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:1.6.2.9-2+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-h323", ver: "1:1.6.2.9-2+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-sounds-main", ver: "1:1.6.2.9-2+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dahdi", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-mobile", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-modules", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-mp3", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-mysql", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-ooh323", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-voicemail", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-voicemail-imapstorage", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-voicemail-odbcstorage", ver: "1:1.8.13.1~dfsg-1", rls: "DEB7" ) ) != NULL){
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

