if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703558" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2016-0636", "CVE-2016-0686", "CVE-2016-0687", "CVE-2016-0695", "CVE-2016-3425", "CVE-2016-3426", "CVE-2016-3427" );
	script_name( "Debian Security Advisory DSA 3558-1 (openjdk-7 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-04-26 00:00:00 +0200 (Tue, 26 Apr 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3558.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "openjdk-7 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 7u101-2.6.6-1~deb8u1.

We recommend that you upgrade your openjdk-7 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
discovered in OpenJDK, an implementation of the Oracle Java platform, resulting
in breakouts of the Java sandbox, denial of service or information disclosure." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:amd64", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm:i386", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-dbg:amd64", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-dbg:i386", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-demo", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-doc", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jdk:amd64", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jdk:i386", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre:amd64", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre:i386", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:amd64", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless:i386", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:amd64", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero:i386", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-source", ver: "7u101-2.6.6-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

