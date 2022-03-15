if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703282" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-4171" );
	script_name( "Debian Security Advisory DSA 3282-1 (strongswan - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-08 00:00:00 +0200 (Mon, 08 Jun 2015)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3282.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "strongswan on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 4.5.2-1.5+deb7u7.

For the stable distribution (jessie), this problem has been fixed in
version 5.2.1-6+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 5.3.1-1.

For the unstable distribution (sid), this problem has been fixed in
version 5.3.1-1.

We recommend that you upgrade your strongswan packages." );
	script_tag( name: "summary", value: "Alexander E. Patrakov discovered an
issue in strongSwan, an IKE/IPsec suite used to establish IPsec protected links.

When an IKEv2 client authenticates the server with certificates and the
client authenticates itself to the server using pre-shared key or EAP,
the constraints on the server certificate are only enforced by the
client after all authentication steps are completed successfully. A
rogue server which can authenticate using a valid certificate issued by
any CA trusted by the client could trick the user into continuing the
authentication, revealing the username and password digest (for EAP) or
even the cleartext password (if EAP-GTC is accepted)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libstrongswan", ver: "4.5.2-1.5+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan", ver: "4.5.2-1.5+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "4.5.2-1.5+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "4.5.2-1.5+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "4.5.2-1.5+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-nm", ver: "4.5.2-1.5+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "strongswan-starter", ver: "4.5.2-1.5+deb7u7", rls: "DEB7" ) ) != NULL){
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

