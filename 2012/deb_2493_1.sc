if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71471" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2012-2947", "CVE-2012-2948", "CVE-2011-2666" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:05:29 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2493-1 (asterisk)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202493-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in Asterisk, a PBX and
telephony toolkit.

CVE-2012-2947
The IAX2 channel driver allows remote attackers to cause a
denial of service (daemon crash) by placing a call on hold
(when a certain mohinterpret setting is enabled).

CVE-2012-2948
The Skinny channel driver allows remote authenticated users to
cause a denial of service (NULL pointer dereference and daemon
crash) by closing a connection in off-hook mode.

In addition, it was discovered that Asterisk does not set the
alwaysauthreject option by default in the SIP channel driver.  This
allows remote attackers to observe a difference in response behavior
and check for the presence of account names.  (CVE-2011-2666)  System
administrators concerned by this user enumerating vulnerability should
enable the alwaysauthreject option in the configuration.  We do not
plan to change the default setting in the stable version
(Asterisk 1.6) in order to preserve backwards compatibility.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.6.2.9-2+squeeze6.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 1:1.8.13.0~dfsg-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your asterisk packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to asterisk
announced via advisory DSA 2493-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1:1.6.2.9-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:1.6.2.9-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:1.6.2.9-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:1.6.2.9-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:1.6.2.9-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-h323", ver: "1:1.6.2.9-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-sounds-main", ver: "1:1.6.2.9-2+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dahdi", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-mobile", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-modules", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-mp3", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-mysql", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-ooh323", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-voicemail", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-voicemail-imapstorage", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-voicemail-odbcstorage", ver: "1:1.8.13.0~dfsg-1", rls: "DEB7" ) ) != NULL){
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

