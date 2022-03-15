if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702810" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4164" );
	script_name( "Debian Security Advisory DSA 2810-1 (ruby1.9.1 - heap overflow)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-12-04 00:00:00 +0100 (Wed, 04 Dec 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2810.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "ruby1.9.1 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.9.2.0-2+deb6u2.

For the stable distribution (wheezy), this problem has been fixed in
version 1.9.3.194-8.1+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 1.9.3.484-1.

We recommend that you upgrade your ruby1.9.1 packages." );
	script_tag( name: "summary", value: "Charlie Somerville discovered that Ruby incorrectly handled floating
point number conversion. If an application using Ruby accepted untrusted
input strings and converted them to floating point numbers, an attacker
able to provide such input could cause the application to crash or,
possibly, execute arbitrary code with the privileges of the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libruby1.9.1", ver: "1.9.2.0-2+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libruby1.9.1-dbg", ver: "1.9.2.0-2+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtcltk-ruby1.9.1", ver: "1.9.2.0-2+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ri1.9.1", ver: "1.9.2.0-2+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1", ver: "1.9.2.0-2+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1-dev", ver: "1.9.2.0-2+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1-elisp", ver: "1.9.2.0-2+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1-examples", ver: "1.9.2.0-2+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1-full", ver: "1.9.2.0-2+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libruby1.9.1", ver: "1.9.3.194-8.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libruby1.9.1-dbg", ver: "1.9.3.194-8.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtcltk-ruby1.9.1", ver: "1.9.3.194-8.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ri1.9.1", ver: "1.9.3.194-8.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1", ver: "1.9.3.194-8.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1-dev", ver: "1.9.3.194-8.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1-examples", ver: "1.9.3.194-8.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1-full", ver: "1.9.3.194-8.1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.3", ver: "1.9.3.194-8.1+deb7u2", rls: "DEB7" ) ) != NULL){
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

