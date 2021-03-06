if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703623" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-5387" );
	script_name( "Debian Security Advisory DSA 3623-1 (apache2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-07-20 00:00:00 +0200 (Wed, 20 Jul 2016)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3623.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "apache2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 2.4.10-10+deb8u5.

We recommend that you upgrade your apache2 packages." );
	script_tag( name: "summary", value: "Scott Geary of VendHQ discovered that the
Apache HTTPD server used the value of the Proxy header from HTTP requests to
initialize the HTTP_PROXY environment variable for CGI scripts, which in turn was
incorrectly used by certain HTTP client implementations to configure the
proxy for outgoing HTTP requests. A remote attacker could possibly use
this flaw to redirect HTTP requests performed by a CGI script to an
attacker-controlled proxy via a malicious HTTP request." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "apache2", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-data", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dbg", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dev", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-doc", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-event", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-itk", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-prefork", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-worker", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-custom", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-pristine", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-utils", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2.2-common", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-macro", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-proxy-html", ver: "2.4.10-10+deb8u5", rls: "DEB8" ) ) != NULL){
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

