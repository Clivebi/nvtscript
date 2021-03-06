if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703080" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558" );
	script_name( "Debian Security Advisory DSA 3080-1 (openjdk-7 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-11-29 00:00:00 +0100 (Sat, 29 Nov 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3080.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openjdk-7 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 7u71-2.5.3-2~deb7u1.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 7u71-2.5.3-1.

For the unstable distribution (sid), these problems have been fixed in
version 7u71-2.5.3-1.

We recommend that you upgrade your openjdk-7 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
discovered in OpenJDK, an implementation of the Oracle Java platform, resulting
in the execution of arbitrary code, information disclosure or denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-cacao", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-dbg", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-demo", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-doc", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jdk", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-source", ver: "7u71-2.5.3-2~deb7u1", rls: "DEB7" ) ) != NULL){
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

