if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703919" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_cve_id( "CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10078", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10118", "CVE-2017-10135", "CVE-2017-10176", "CVE-2017-10193", "CVE-2017-10198" );
	script_name( "Debian Security Advisory DSA 3919-1 (openjdk-8 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-25 00:00:00 +0200 (Tue, 25 Jul 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3919.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "openjdk-8 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 8u141-b15-1~deb9u1.

For the unstable distribution (sid), these problems have been fixed in
version 8u141-b15-1.

We recommend that you upgrade your openjdk-8 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in sandbox bypass,
use of insecure cryptography, side channel attacks, information
disclosure, the execution of arbitrary code, denial of service or
bypassing Jar verification." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "openjdk-8-dbg", ver: "8u141-b15-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-8-demo", ver: "8u141-b15-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-8-doc", ver: "8u141-b15-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-8-jdk", ver: "8u141-b15-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-8-jdk-headless", ver: "8u141-b15-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-8-jre", ver: "8u141-b15-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-8-jre-headless", ver: "8u141-b15-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-8-jre-zero", ver: "8u141-b15-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-8-source", ver: "8u141-b15-1~deb9u1", rls: "DEB9" ) ) != NULL){
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

