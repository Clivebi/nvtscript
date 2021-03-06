if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703709" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-4738" );
	script_name( "Debian Security Advisory DSA 3709-1 (libxslt - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-14 17:59:18 +0530 (Mon, 14 Nov 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3709.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "libxslt on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1.1.28-2+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 1.1.29-2.

For the unstable distribution (sid), this problem has been fixed in
version 1.1.29-2.

We recommend that you upgrade your libxslt packages." );
	script_tag( name: "summary", value: "Nick Wellnhofer discovered that the
xsltFormatNumberConversion function in libxslt, an XSLT processing runtime library,
does not properly check for a zero byte terminating the pattern string. This flaw
can be exploited to leak a couple of bytes after the buffer that holds the
pattern string." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxslt1-dbg:amd64", ver: "1.1.29-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1-dbg:i386", ver: "1.1.29-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1-dev:amd64", ver: "1.1.29-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1-dev:i386", ver: "1.1.29-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1.1:amd64", ver: "1.1.29-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1.1:i386", ver: "1.1.29-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxslt1", ver: "1.1.29-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxslt1-dbg", ver: "1.1.29-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xsltproc", ver: "1.1.29-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1-dbg:amd64", ver: "1.1.28-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1-dbg:i386", ver: "1.1.28-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1-dev:amd64", ver: "1.1.28-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1-dev:i386", ver: "1.1.28-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1.1:amd64", ver: "1.1.28-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxslt1.1:i386", ver: "1.1.28-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxslt1", ver: "1.1.28-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxslt1-dbg", ver: "1.1.28-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xsltproc", ver: "1.1.28-2+deb8u2", rls: "DEB8" ) ) != NULL){
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

