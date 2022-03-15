if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703247" );
	script_version( "2019-12-20T08:10:23+0000" );
	script_cve_id( "CVE-2015-1855" );
	script_name( "Debian Security Advisory DSA 3247-1 (ruby2.1 - security update)" );
	script_tag( name: "last_modification", value: "2019-12-20 08:10:23 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-05-02 00:00:00 +0200 (Sat, 02 May 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3247.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "ruby2.1 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 2.1.5-2+deb8u1.

For the testing distribution (stretch), this problem has been fixed in
version 2.1.5-3.

For the unstable distribution (sid), this problem has been fixed in
version 2.1.5-3.

We recommend that you upgrade your ruby2.1 packages." );
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
if(( res = isdpkgvuln( pkg: "libruby2.1", ver: "2.1.5-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.1", ver: "2.1.5-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.1-dev", ver: "2.1.5-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.1-doc", ver: "2.1.5-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.1-tcltk", ver: "2.1.5-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libruby2.1", ver: "2.1.5-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.1", ver: "2.1.5-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.1-dev", ver: "2.1.5-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.1-doc", ver: "2.1.5-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby2.1-tcltk", ver: "2.1.5-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

