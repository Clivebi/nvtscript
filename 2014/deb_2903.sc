if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702903" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-2338" );
	script_name( "Debian Security Advisory DSA 2903-1 (strongswan - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-14 00:00:00 +0200 (Mon, 14 Apr 2014)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2903.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "strongswan on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze),
this problem has been fixed in version 4.4.1-5.5.

For the stable distribution (wheezy), this problem has been fixed in
version 4.5.2-1.5+deb7u3.

For the unstable distribution (sid), this problem has been fixed in
version 5.1.2-4.

We recommend that you upgrade your strongswan packages." );
	script_tag( name: "summary", value: "An authentication bypass vulnerability
was found in charon, the daemon handling IKEv2 in strongSwan, an IKE/IPsec suite.
The state machine handling the security association (IKE_SA) handled some state
transitions incorrectly.

An attacker can trigger the vulnerability by rekeying an unestablished
IKE_SA during the initiation itself. This will trick the IKE_SA state to
established without the need to provide any valid credential.

Vulnerable setups include those actively initiating IKEv2 IKE_SA (like
?clients? or ?roadwarriors?) but also during re-authentication (which
can be initiated by the responder). Installations using IKEv1 (pluto
daemon in strongSwan 4 and earlier, and IKEv1 code in charon 5.x) is not
affected." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "4.4.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "4.4.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "4.4.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "4.4.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "4.4.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "4.4.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "4.4.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "4.5.2-1.5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "4.5.2-1.5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "4.5.2-1.5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "4.5.2-1.5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "4.5.2-1.5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "4.5.2-1.5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "4.5.2-1.5+deb7u3", rls: "DEB7" ) ) != NULL){
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

