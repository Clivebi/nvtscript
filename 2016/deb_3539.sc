if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703539" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-6360" );
	script_name( "Debian Security Advisory DSA 3539-1 (srtp - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-02 00:00:00 +0200 (Sat, 02 Apr 2016)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3539.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "srtp on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 1.4.4+20100615~dfsg-2+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 1.4.5~20130609~dfsg-1.1+deb8u1.

We recommend that you upgrade your srtp packages." );
	script_tag( name: "summary", value: "Randell Jesup and the Firefox team
discovered that srtp, Cisco's reference implementation of the Secure Real-time
Transport Protocol (SRTP), does not properly handle RTP header CSRC count and
extension header length. A remote attacker can exploit this vulnerability to crash
an application linked against libsrtp, resulting in a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libsrtp0", ver: "1.4.4+20100615~dfsg-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsrtp0-dev", ver: "1.4.4+20100615~dfsg-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "srtp-docs", ver: "1.4.4+20100615~dfsg-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "srtp-utils", ver: "1.4.4+20100615~dfsg-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsrtp0", ver: "1.4.5~20130609~dfsg-1.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsrtp0-dev", ver: "1.4.5~20130609~dfsg-1.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "srtp-docs", ver: "1.4.5~20130609~dfsg-1.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "srtp-utils", ver: "1.4.5~20130609~dfsg-1.1+deb8u1", rls: "DEB8" ) ) != NULL){
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

