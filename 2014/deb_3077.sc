if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703077" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558" );
	script_name( "Debian Security Advisory DSA 3077-1 (openjdk-6 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-11-26 00:00:00 +0100 (Wed, 26 Nov 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3077.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openjdk-6 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 6b33-1.13.5-2~deb7u1.

We recommend that you upgrade your openjdk-6 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in the execution
of arbitrary code, information disclosure or denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icedtea-6-jre-cacao", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-6-jre-jamvm", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-dbg", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-demo", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-doc", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jdk", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-zero", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-source", ver: "6b33-1.13.5-2~deb7u1", rls: "DEB7" ) ) != NULL){
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

