if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703430" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8035", "CVE-2015-8241", "CVE-2015-8317" );
	script_name( "Debian Security Advisory DSA 3430-1 (libxml2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-23 00:00:00 +0100 (Wed, 23 Dec 2015)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3430.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "libxml2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), these problems have been fixed
in version 2.8.0+dfsg1-7+wheezy5.

For the stable distribution (jessie), these problems have been fixed in
version 2.9.1+dfsg1-5+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 2.9.3+dfsg1-1 or earlier versions.

For the unstable distribution (sid), these problems have been fixed in
version 2.9.3+dfsg1-1 or earlier versions.

We recommend that you upgrade your libxml2 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in libxml2, a library providing
support to read, modify and write XML and HTML files. A remote attacker
could provide a specially crafted XML or HTML file that, when processed
by an application using libxml2, would cause that application to use an
excessive amount of CPU, leak potentially sensitive information, or
crash the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.8.0+dfsg1-7+wheezy5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.8.0+dfsg1-7+wheezy5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.8.0+dfsg1-7+wheezy5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.8.0+dfsg1-7+wheezy5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.8.0+dfsg1-7+wheezy5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils-dbg", ver: "2.8.0+dfsg1-7+wheezy5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.8.0+dfsg1-7+wheezy5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.8.0+dfsg1-7+wheezy5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.9.1+dfsg1-5+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.9.1+dfsg1-5+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.9.1+dfsg1-5+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.9.1+dfsg1-5+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.9.1+dfsg1-5+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils-dbg", ver: "2.9.1+dfsg1-5+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.9.1+dfsg1-5+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.9.1+dfsg1-5+deb8u1", rls: "DEB8" ) ) != NULL){
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

