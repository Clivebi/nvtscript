if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703234" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0470", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488" );
	script_name( "Debian Security Advisory DSA 3234-1 (openjdk-6 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-04-24 00:00:00 +0200 (Fri, 24 Apr 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3234.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openjdk-6 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 6b35-1.13.7-1~deb7u1.

We recommend that you upgrade your openjdk-6 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
discovered in OpenJDK, an implementation of the Oracle Java platform, resulting
in the execution of arbitrary code, breakouts of the Java sandbox, information
disclosure or denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao:amd64", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao:i386", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm:amd64", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm:i386", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-dbg:amd64", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-dbg:i386", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-demo", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-doc", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jdk:amd64", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jdk:i386", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre:amd64", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre:i386", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless:amd64", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless:i386", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero:amd64", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero:i386", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-source", ver: "6b35-1.13.7-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

