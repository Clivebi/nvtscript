if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702744" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4244", "CVE-2013-4232", "CVE-2013-4231" );
	script_name( "Debian Security Advisory DSA 2744-1 (tiff - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-08-27 00:00:00 +0200 (Tue, 27 Aug 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2744.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "tiff on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 3.9.4-5+squeeze10.

For the stable distribution (wheezy), these problems have been fixed in
version 4.0.2-6+deb7u2.

For the unstable distribution (sid), these problems have been fixed in
version 4.0.3-3.

We recommend that you upgrade your tiff packages." );
	script_tag( name: "summary", value: "Pedro Ribeiro and Huzaifa S. Sidhpurwala discovered multiple
vulnerabilities in various tools shipped by the tiff library. Processing
a malformed file may lead to denial of service or the execution of
arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libtiff-doc", ver: "3.9.4-5+squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "3.9.4-5+squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-tools", ver: "3.9.4-5+squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff4", ver: "3.9.4-5+squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.9.4-5+squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.9.4-5+squeeze10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-doc", ver: "4.0.2-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "4.0.2-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff-tools", ver: "4.0.2-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff5", ver: "4.0.2-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff5-alt-dev", ver: "4.0.2-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiff5-dev", ver: "4.0.2-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtiffxx5", ver: "4.0.2-6+deb7u2", rls: "DEB7" ) ) != NULL){
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

