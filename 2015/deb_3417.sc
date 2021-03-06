if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703417" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-7940" );
	script_name( "Debian Security Advisory DSA 3417-1 (bouncycastle - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-14 00:00:00 +0100 (Mon, 14 Dec 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3417.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "bouncycastle on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 1.44+dfsg-3.1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 1.49+dfsg-3+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 1.51-2.

We recommend that you upgrade your bouncycastle packages." );
	script_tag( name: "summary", value: "Tibor Jager, Jorg Schwenk, and
Juraj Somorovsky, from Horst Gortz Institute for IT Security, published a
paper in ESORICS 2015 where they describe an invalid curve attack in Bouncy
Castle Crypto, a Java library for cryptography. An attacker is able to recover
private Elliptic Curve keys from different applications, for example, TLS servers." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libbcmail-java", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcmail-java-doc", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcmail-java-gcj", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcpg-java", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcpg-java-doc", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcpg-java-gcj", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcprov-java", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcprov-java-doc", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcprov-java-gcj", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbctsp-java", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbctsp-java-doc", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbctsp-java-gcj", ver: "1.44+dfsg-3.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcmail-java", ver: "1.49+dfsg-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcmail-java-doc", ver: "1.49+dfsg-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcpg-java", ver: "1.49+dfsg-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcpg-java-doc", ver: "1.49+dfsg-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcpkix-java", ver: "1.49+dfsg-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcpkix-java-doc", ver: "1.49+dfsg-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcprov-java", ver: "1.49+dfsg-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbcprov-java-doc", ver: "1.49+dfsg-3+deb8u1", rls: "DEB8" ) ) != NULL){
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

