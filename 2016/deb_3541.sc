if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703541" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2015-8770" );
	script_name( "Debian Security Advisory DSA 3541-1 (roundcube - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-05 00:00:00 +0200 (Tue, 05 Apr 2016)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3541.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9)" );
	script_tag( name: "affected", value: "roundcube on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 0.7.2-9+deb7u2.

For the testing (stretch) and unstable (sid) distributions, this
problem has been fixed in version 1.1.4+dfsg.1-1.

We recommend that you upgrade your roundcube packages." );
	script_tag( name: "summary", value: "High-Tech Bridge Security Research Lab
discovered that Roundcube, a webmail client, contained a path traversal
vulnerability. This flaw could be exploited by an attacker to access sensitive
files on the server, or even execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "roundcube", ver: "0.7.2-9+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-core", ver: "0.7.2-9+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-mysql", ver: "0.7.2-9+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-pgsql", ver: "0.7.2-9+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-plugins", ver: "0.7.2-9+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube", ver: "1.1.4+dfsg.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-core", ver: "1.1.4+dfsg.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-mysql", ver: "1.1.4+dfsg.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-pgsql", ver: "1.1.4+dfsg.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-plugins", ver: "1.1.4+dfsg.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-sqlite3", ver: "1.1.4+dfsg.1-1", rls: "DEB9" ) ) != NULL){
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

