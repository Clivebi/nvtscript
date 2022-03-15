if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702840" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-2139" );
	script_name( "Debian Security Advisory DSA 2840-1 (srtp - buffer overflow)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-10 00:00:00 +0100 (Fri, 10 Jan 2014)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2840.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "srtp on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.4.4~dfsg-6+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in
version 1.4.4+20100615~dfsg-2+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1.4.5~20130609~dfsg-1.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.5~20130609~dfsg-1.

We recommend that you upgrade your srtp packages." );
	script_tag( name: "summary", value: "Fernando Russ from Groundworks Technologies reported a buffer overflow
flaw in srtp, Cisco's reference implementation of the Secure Real-time
Transport Protocol (SRTP), in how the
crypto_policy_set_from_profile_for_rtp() function applies
cryptographic profiles to an srtp_policy. A remote attacker could
exploit this vulnerability to crash an application linked against
libsrtp, resulting in a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libsrtp0", ver: "1.4.4~dfsg-6+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsrtp0-dev", ver: "1.4.4~dfsg-6+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "srtp-docs", ver: "1.4.4~dfsg-6+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "srtp-utils", ver: "1.4.4~dfsg-6+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsrtp0", ver: "1.4.4+20100615~dfsg-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsrtp0-dev", ver: "1.4.4+20100615~dfsg-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "srtp-docs", ver: "1.4.4+20100615~dfsg-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "srtp-utils", ver: "1.4.4+20100615~dfsg-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

