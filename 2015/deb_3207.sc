if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703207" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-2684" );
	script_name( "Debian Security Advisory DSA 3207-1 (shibboleth-sp2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-28 00:00:00 +0100 (Sat, 28 Mar 2015)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3207.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "shibboleth-sp2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 2.4.3+dfsg-5+deb7u1.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 2.5.3+dfsg-2.

For the unstable distribution (sid), this problem has been fixed in
version 2.5.3+dfsg-2.

We recommend that you upgrade your shibboleth-sp2 packages." );
	script_tag( name: "summary", value: "A denial of service vulnerability
was found in the Shibboleth (an federated identity framework) Service Provider.
When processing certain malformed SAML message generated by an authenticated
attacker, the daemon could crash." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache2-mod-shib2", ver: "2.4.3+dfsg-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libshibsp-dev", ver: "2.4.3+dfsg-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libshibsp-doc", ver: "2.4.3+dfsg-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libshibsp5:amd64", ver: "2.4.3+dfsg-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libshibsp5:i386", ver: "2.4.3+dfsg-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "shibboleth-sp2-schemas", ver: "2.4.3+dfsg-5+deb7u1", rls: "DEB7" ) ) != NULL){
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
