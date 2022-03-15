if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703568" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-4008" );
	script_name( "Debian Security Advisory DSA 3568-1 (libtasn1-6 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-05 00:00:00 +0200 (Thu, 05 May 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3568.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "libtasn1-6 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 4.2-3+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 4.8-1.

For the unstable distribution (sid), this problem has been fixed in
version 4.8-1.

We recommend that you upgrade your libtasn1-6 packages." );
	script_tag( name: "summary", value: "Pascal Cuoq and Miod Vallat discovered
that Libtasn1, a library to manage ASN.1 structures, does not correctly handle
certain malformed DER certificates. A remote attacker can take advantage of this
flaw to cause an application using the Libtasn1 library to hang, resulting in a
denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libtasn1-3-bin", ver: "4.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-6:amd64", ver: "4.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-6:i386", ver: "4.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-6-dbg:amd64", ver: "4.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-6-dbg:i386", ver: "4.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-6-dev", ver: "4.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-bin", ver: "4.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-doc", ver: "4.2-3+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-3-bin", ver: "4.8-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-6:amd64", ver: "4.8-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-6:i386", ver: "4.8-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-6-dev", ver: "4.8-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-bin", ver: "4.8-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtasn1-doc", ver: "4.8-1", rls: "DEB9" ) ) != NULL){
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

