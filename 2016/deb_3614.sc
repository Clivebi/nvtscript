if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703614" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-3092" );
	script_name( "Debian Security Advisory DSA 3614-1 (tomcat7 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-07-02 00:00:00 +0200 (Sat, 02 Jul 2016)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3614.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "tomcat7 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this
problem has been fixed in version 7.0.56-3+deb8u3.

For the testing distribution (stretch), this problem has been fixed
in version 7.0.70-1.

For the unstable distribution (sid), this problem has been fixed in
version 7.0.70-1.

We recommend that you upgrade your tomcat7 packages." );
	script_tag( name: "summary", value: "The TERASOLUNA Framework Development Team
discovered a denial of service vulnerability in Apache Commons FileUpload, a package
to make it easy to add robust, high-performance, file upload capability to servlets
and web applications. A remote attacker can take advantage of this flaw
by sending file upload requests that cause the HTTP server using the
Apache Commons Fileupload library to become unresponsive, preventing the
server from servicing other requests.

Apache Tomcat uses a package renamed copy of Apache Commons FileUpload
to implement the file upload requirements of the Servlet specification
and is therefore also vulnerable to the denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.56-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.56-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.56-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.56-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.56-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.56-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.56-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.56-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.56-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.70-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.70-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.70-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.70-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.70-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.70-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.70-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.70-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.70-1", rls: "DEB9" ) ) != NULL){
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

