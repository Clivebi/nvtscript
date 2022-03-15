if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702722" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2470", "CVE-2013-2459", "CVE-2013-2454", "CVE-2013-2463", "CVE-2013-1500", "CVE-2013-2451", "CVE-2013-2445", "CVE-2013-1571", "CVE-2013-2450", "CVE-2013-2446", "CVE-2013-2460", "CVE-2013-2472", "CVE-2013-2471", "CVE-2013-2448", "CVE-2013-2444", "CVE-2013-2447", "CVE-2013-2473", "CVE-2013-2443", "CVE-2013-2452", "CVE-2013-2469", "CVE-2013-2461", "CVE-2013-2458", "CVE-2013-2455", "CVE-2013-2412", "CVE-2013-2449", "CVE-2013-2456", "CVE-2013-2465", "CVE-2013-2407", "CVE-2013-2457", "CVE-2013-2453" );
	script_name( "Debian Security Advisory DSA 2722-1 (openjdk-7 - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-15 00:00:00 +0200 (Mon, 15 Jul 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2722.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openjdk-7 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 7u25-2.3.10-1~deb7u1. In addition icedtea-web needed to be
updated to 1.4-3~deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 7u25-2.3.10-1.

We recommend that you upgrade your openjdk-7 packages." );
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
if(( res = isdpkgvuln( pkg: "icedtea-7-jre-jamvm", ver: "7u25-2.3.10-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-dbg", ver: "7u25-2.3.10-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-demo", ver: "7u25-2.3.10-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-doc", ver: "7u25-2.3.10-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jdk", ver: "7u25-2.3.10-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre", ver: "7u25-2.3.10-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-headless", ver: "7u25-2.3.10-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-lib", ver: "7u25-2.3.10-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-jre-zero", ver: "7u25-2.3.10-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-7-source", ver: "7u25-2.3.10-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

