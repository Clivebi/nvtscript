if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703896" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_cve_id( "CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7659", "CVE-2017-7668", "CVE-2017-7679" );
	script_name( "Debian Security Advisory DSA 3896-1 (apache2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-22 00:00:00 +0200 (Thu, 22 Jun 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3896.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "apache2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 2.4.10-10+deb8u9. The oldstable distribution (jessie) is not
affected by CVE-2017-7659
.

For the stable distribution (stretch), these problems have been fixed in
version 2.4.25-3+deb9u1.

For the unstable distribution (sid), these problems have been fixed in
version 2.4.25-4.

We recommend that you upgrade your apache2 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been found in the Apache HTTPD server.

CVE-2017-3167
Emmanuel Dreyfus reported that the use of ap_get_basic_auth_pw() by
third-party modules outside of the authentication phase may lead to
authentication requirements being bypassed.

CVE-2017-3169
Vasileios Panopoulos of AdNovum Informatik AG discovered that
mod_ssl may dereference a NULL pointer when third-party modules call
ap_hook_process_connection() during an HTTP request to an HTTPS port
leading to a denial of service.

CVE-2017-7659
Robert Swiecki reported that a specially crafted HTTP/2 request
could cause mod_http2 to dereference a NULL pointer and crash the
server process.

CVE-2017-7668
Javier Jimenez reported that the HTTP strict parsing contains a
flaw leading to a buffer overread in ap_find_token(). A remote
attacker can take advantage of this flaw by carefully crafting a
sequence of request headers to cause a segmentation fault, or to
force ap_find_token() to return an incorrect value.

CVE-2017-7679
ChenQin and Hanno Boeck reported that mod_mime can read one byte
past the end of a buffer when sending a malicious Content-Type
response header." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "apache2", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-data", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dbg", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dev", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-doc", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-event", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-itk", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-prefork", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-mpm-worker", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-custom", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-pristine", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-utils", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2.2-common", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-macro", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-proxy-html", ver: "2.4.10-10+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2", ver: "2.4.25-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.25-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-data", ver: "2.4.25-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dbg", ver: "2.4.25-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-dev", ver: "2.4.25-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-doc", ver: "2.4.25-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-ssl-dev", ver: "2.4.25-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-custom", ver: "2.4.25-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-suexec-pristine", ver: "2.4.25-3+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apache2-utils", ver: "2.4.25-3+deb9u1", rls: "DEB9" ) ) != NULL){
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

