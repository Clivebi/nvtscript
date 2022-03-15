if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703891" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2017-5664" );
	script_name( "Debian Security Advisory DSA 3891-1 (tomcat8 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-22 00:00:00 +0200 (Thu, 22 Jun 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3891.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10|8)" );
	script_tag( name: "affected", value: "tomcat8 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 8.0.14-1+deb8u10.

For the stable distribution (stretch), this problem has been fixed in
version 8.5.14-1+deb9u1.

For the testing distribution (buster), this problem has been fixed
in version 8.5.14-2.

For the unstable distribution (sid), this problem has been fixed in
version 8.5.14-2.

We recommend that you upgrade your tomcat8 packages." );
	script_tag( name: "summary", value: "Aniket Nandkishor Kulkarni discovered that in tomcat8, a servlet and
JSP engine, static error pages used the original request's HTTP method
to serve content, instead of systematically using the GET method. This
could under certain conditions result in undesirable results,
including the replacement or removal of the custom error page." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libservlet3.1-java", ver: "8.5.14-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.1-java-doc", ver: "8.5.14-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat8-embed-java", ver: "8.5.14-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.5.14-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8", ver: "8.5.14-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-admin", ver: "8.5.14-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-common", ver: "8.5.14-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-docs", ver: "8.5.14-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-examples", ver: "8.5.14-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-user", ver: "8.5.14-1+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.1-java", ver: "8.5.14-2", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.1-java-doc", ver: "8.5.14-2", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat8-embed-java", ver: "8.5.14-2", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.5.14-2", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8", ver: "8.5.14-2", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-admin", ver: "8.5.14-2", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-common", ver: "8.5.14-2", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-docs", ver: "8.5.14-2", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-examples", ver: "8.5.14-2", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-user", ver: "8.5.14-2", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.1-java", ver: "8.0.14-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.1-java-doc", ver: "8.0.14-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.0.14-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8", ver: "8.0.14-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-admin", ver: "8.0.14-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-common", ver: "8.0.14-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-docs", ver: "8.0.14-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-examples", ver: "8.0.14-1+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat8-user", ver: "8.0.14-1+deb8u10", rls: "DEB8" ) ) != NULL){
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

