if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702912" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-0462", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2403", "CVE-2014-2405", "CVE-2014-2412", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427" );
	script_name( "Debian Security Advisory DSA 2912-1 (openjdk-6 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-24 00:00:00 +0200 (Thu, 24 Apr 2014)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2912.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "openjdk-6 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed
in version 6b31-1.13.3-1~deb6u1.

For the stable distribution (wheezy), these problems have been fixed in
version 6b31-1.13.3-1~deb7u1.

For the testing distribution (jessie), these problems have been fixed in
version 6b31-1.13.3-1.

For the unstable distribution (sid), these problems have been fixed in
version 6b31-1.13.3-1.

We recommend that you upgrade your openjdk-6 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in the execution
of arbitrary code, breakouts of the Java sandbox, information disclosure
or denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b31-1.13.3-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-dbg", ver: "6b31-1.13.3-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-demo", ver: "6b31-1.13.3-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-doc", ver: "6b31-1.13.3-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jdk", ver: "6b31-1.13.3-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b31-1.13.3-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b31-1.13.3-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b31-1.13.3-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b31-1.13.3-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-source", ver: "6b31-1.13.3-1~deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-dbg", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-demo", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-doc", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jdk", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-source", ver: "6b31-1.13.3-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

