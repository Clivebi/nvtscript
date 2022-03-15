if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703398" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-8023" );
	script_name( "Debian Security Advisory DSA 3398-1 (strongswan - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-16 00:00:00 +0100 (Mon, 16 Nov 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3398.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9|8)" );
	script_tag( name: "affected", value: "strongswan on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 4.5.2-1.5+deb7u8.

For the stable distribution (jessie), this problem has been fixed in
version 5.2.1-6+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 5.3.3-3.

For the unstable distribution (sid), this problem has been fixed in
version 5.3.3-3.

We recommend that you upgrade your strongswan packages." );
	script_tag( name: "summary", value: "Tobias Brunner found an authentication
bypass vulnerability in strongSwan, an IKE/IPsec suite.

Due to insufficient validation of its local state the server
implementation of the EAP-MSCHAPv2 protocol in the eap-mschapv2 plugin
can be tricked into successfully concluding the authentication without
providing valid credentials.

It's possible to recognize such attacks by looking at the server logs.
The following log message would be seen during the client
authentication:

EAP method EAP_MSCHAPV2 succeeded, no MSK established" );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "4.5.2-1.5+deb7u8", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "4.5.2-1.5+deb7u8", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "4.5.2-1.5+deb7u8", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "4.5.2-1.5+deb7u8", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "4.5.2-1.5+deb7u8", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "4.5.2-1.5+deb7u8", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "4.5.2-1.5+deb7u8", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "charon-cmd", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcharon-extra-plugins", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan-extra-plugins", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan-standard-plugins", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-charon", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ike", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-libcharon", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "5.3.3-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "charon-cmd", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcharon-extra-plugins", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan-extra-plugins", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan-standard-plugins", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-charon", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ike", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-libcharon", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "5.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
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

