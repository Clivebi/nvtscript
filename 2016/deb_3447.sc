if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703447" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2013-4444", "CVE-2014-0075", "CVE-2014-0099", "CVE-2014-0227", "CVE-2014-0230", "CVE-2014-7810" );
	script_name( "Debian Security Advisory DSA 3447-1 (tomcat7 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-01-17 00:00:00 +0100 (Sun, 17 Jan 2016)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3447.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|7|8)" );
	script_tag( name: "affected", value: "tomcat7 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution
(wheezy), this problem has been fixed in version 7.0.28-4+deb7u3. This update
also provides fixes for CVE-2013-4444, CVE-2014-0075, CVE-2014-0099, CVE-2014-0227
and CVE-2014-0230, which were all fixed for the stable distribution (jessie)
already.

For the stable distribution (jessie), this problem has been fixed in
version 7.0.56-3+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 7.0.61-1.

For the unstable distribution (sid), this problem has been fixed in
version 7.0.61-1.

We recommend that you upgrade your tomcat7 packages." );
	script_tag( name: "summary", value: "It was discovered that malicious web
applications could use the Expression Language to bypass protections of a Security
Manager as expressions were evaluated within a privileged code section." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.61-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.61-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.61-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.61-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.61-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.61-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.61-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.61-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.61-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.28-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.28-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.28-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.28-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.28-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.28-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.28-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.28-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.28-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.56-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.56-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.56-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.56-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.56-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.56-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.56-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.56-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.56-3+deb8u1", rls: "DEB8" ) ) != NULL){
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

