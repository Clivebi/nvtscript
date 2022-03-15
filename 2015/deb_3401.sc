if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703401" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-4871" );
	script_name( "Debian Security Advisory DSA 3401-1 (openjdk-7 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-22 00:00:00 +0100 (Sun, 22 Nov 2015)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3401.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "openjdk-7 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution
(wheezy), this problem has been fixed in version 7u91-2.6.3-1~deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 7u91-2.6.3-1~deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 7u91-2.6.3-1.

We recommend that you upgrade your openjdk-7 packages." );
	script_tag( name: "summary", value: "It was discovered that rebinding
a receiver of a direct method handle
may allow a protected method to be accessed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-cacao:amd64", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-cacao:i386", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:amd64", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:i386", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-dbg:amd64", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-dbg:i386", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-demo", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-doc", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jdk:amd64", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jdk:i386", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre:amd64", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre:i386", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:amd64", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:i386", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:amd64", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:i386", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-source", ver: "7u91-2.6.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:amd64", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:i386", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-dbg:amd64", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-dbg:i386", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-demo", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-doc", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jdk:amd64", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jdk:i386", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre:amd64", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre:i386", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headlesss:amd64", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headlesss:i386", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:amd64", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:i386", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-source", ver: "7u91-2.6.3-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

