if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703597" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2012-0876", "CVE-2012-6702", "CVE-2016-5300" );
	script_name( "Debian Security Advisory DSA 3597-1 (expat - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-06-07 00:00:00 +0200 (Tue, 07 Jun 2016)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3597.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "expat on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 2.1.0-6+deb8u3.

For the unstable distribution (sid), these problems have been fixed in
version 2.1.1-3.

We recommend that you upgrade your expat packages." );
	script_tag( name: "summary", value: "Two related issues have been discovered
in Expat, a C library for parsing XML.

CVE-2012-6702It was introduced when
CVE-2012-0876

was addressed. Stefan Srensen discovered that the use of the function
XML_Parse() seeds the random number generator generating repeated outputs
for rand() calls.

CVE-2016-5300It is the product of an incomplete solution for
CVE-2012-0876
.
The parser poorly seeds the random number generator allowing an attacker to
cause a denial of service (CPU consumption) via an XML file with crafted
identifiers.

You might need to manually restart programs and services using expat
libraries." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "expat", ver: "2.1.0-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib64expat1", ver: "2.1.0-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib64expat1-dev", ver: "2.1.0-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1:amd64", ver: "2.1.0-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1:i386", ver: "2.1.0-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1-dev:amd64", ver: "2.1.0-6+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1-dev:i386", ver: "2.1.0-6+deb8u3", rls: "DEB8" ) ) != NULL){
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

