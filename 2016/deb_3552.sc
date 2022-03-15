if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703552" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-0096", "CVE-2014-0119", "CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763" );
	script_name( "Debian Security Advisory DSA 3552-1 (tomcat7 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-04-17 00:00:00 +0200 (Sun, 17 Apr 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-19 01:29:00 +0000 (Thu, 19 Jul 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3552.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8|9)" );
	script_tag( name: "affected", value: "tomcat7 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 7.0.28-4+deb7u4. This update also fixes
CVE-2014-0119 and CVE-2014-0096 .

For the stable distribution (jessie), these problems have been fixed in
version 7.0.56-3+deb8u2.

For the testing distribution (stretch), these problems have been fixed
in version 7.0.68-1.

For the unstable distribution (sid), these problems have been fixed in
version 7.0.68-1.

We recommend that you upgrade your tomcat7 packages." );
	script_tag( name: "summary", value: "Multiple security vulnerabilities have
been discovered in the Tomcat servlet and JSP engine, which may result in information
disclosure, the bypass of CSRF protections and bypass of the SecurityManager." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version
using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.28-4+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.28-4+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.28-4+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.28-4+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.28-4+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.28-4+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.28-4+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.28-4+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.28-4+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.56-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.56-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.56-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.56-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.56-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.56-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.56-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.56-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.56-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.68-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.68-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.68-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.68-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.68-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.68-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.68-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.68-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.68-1", rls: "DEB9" ) ) != NULL){
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

