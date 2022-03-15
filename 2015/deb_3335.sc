if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703335" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-5475" );
	script_name( "Debian Security Advisory DSA 3335-1 (request-tracker4 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-13 00:00:00 +0200 (Thu, 13 Aug 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3335.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "request-tracker4 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 4.0.7-5+deb7u4. The oldstable distribution
(wheezy) is only affected by CVE-2015-5475.

For the stable distribution (jessie), these problems have been fixed in
version 4.2.8-3+deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 4.2.11-2.

We recommend that you upgrade your request-tracker4 packages." );
	script_tag( name: "summary", value: "It was discovered that Request Tracker,
an extensible trouble-ticket tracking system is susceptible to a cross-site
scripting attack via the user and group rights management pages (CVE-2015-5475
) and via the cryptography interface, allowing an attacker with a carefully-crafted
key to inject JavaScript into RT's user interface. Installations which
use neither GnuPG nor S/MIME are unaffected by the second cross-site
scripting vulnerability." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "request-tracker4", ver: "4.0.7-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt4-apache2", ver: "4.0.7-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt4-clients", ver: "4.0.7-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt4-db-mysql", ver: "4.0.7-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt4-db-postgresql", ver: "4.0.7-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt4-db-sqlite", ver: "4.0.7-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt4-fcgi", ver: "4.0.7-5+deb7u4", rls: "DEB7" ) ) != NULL){
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

