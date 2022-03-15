if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703245" );
	script_version( "2019-12-20T08:10:23+0000" );
	script_cve_id( "CVE-2015-1855" );
	script_name( "Debian Security Advisory DSA 3245-1 (ruby1.8 - security update)" );
	script_tag( name: "last_modification", value: "2019-12-20 08:10:23 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-05-02 00:00:00 +0200 (Sat, 02 May 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3245.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ruby1.8 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 1.8.7.358-7.1+deb7u3.

We recommend that you upgrade your ruby1.8 packages." );
	script_tag( name: "summary", value: "It was discovered that the Ruby OpenSSL extension, part of the interpreter
for the Ruby language, did not properly implement hostname matching, in
violation of RFC 6125. This could allow remote attackers to perform a
man-in-the-middle attack via crafted SSL certificates." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libruby1.8", ver: "1.8.7.358-7.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libruby1.8-dbg", ver: "1.8.7.358-7.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtcltk-ruby1.8", ver: "1.8.7.358-7.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ri1.8", ver: "1.8.7.358-7.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.8", ver: "1.8.7.358-7.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.8-dev", ver: "1.8.7.358-7.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.8-examples", ver: "1.8.7.358-7.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.8-full", ver: "1.8.7.358-7.1+deb7u3", rls: "DEB7" ) ) != NULL){
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

