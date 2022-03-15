if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702725" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-4534", "CVE-2012-3544", "CVE-2013-2067", "CVE-2012-5885", "CVE-2012-5887", "CVE-2012-4431", "CVE-2012-2733", "CVE-2012-5886", "CVE-2012-3546" );
	script_name( "Debian Security Advisory DSA 2725-1 (tomcat6 - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-18 00:00:00 +0200 (Thu, 18 Jul 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2725.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "tomcat6 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 6.0.35-1+squeeze3. This update also provides fixes for
CVE-2012-2733,
CVE-2012-3546,
CVE-2012-4431,
CVE-2012-4534,
CVE-2012-5885,
CVE-2012-5886 and
CVE-2012-5887
,
which were all fixed for stable already.

For the stable distribution (wheezy), these problems have been fixed in
version 6.0.35-6+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your tomcat6 packages." );
	script_tag( name: "summary", value: "Two security issues have been found in the Tomcat servlet and JSP engine:

CVE-2012-3544
The input filter for chunked transfer encodings could trigger high
resource consumption through malformed CRLF sequences, resulting in
denial of service.

CVE-2013-2067
The FormAuthenticator module was vulnerable to session fixation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libservlet2.5-java", ver: "6.0.35-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet2.5-java-doc", ver: "6.0.35-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.35-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6", ver: "6.0.35-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-admin", ver: "6.0.35-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-common", ver: "6.0.35-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-docs", ver: "6.0.35-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-examples", ver: "6.0.35-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-user", ver: "6.0.35-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet2.4-java", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet2.5-java", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libservlet2.5-java-doc", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-admin", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-common", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-docs", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-examples", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-extras", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat6-user", ver: "6.0.35-6+deb7u1", rls: "DEB7" ) ) != NULL){
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

