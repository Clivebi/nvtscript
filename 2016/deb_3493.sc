if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703493" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-0729" );
	script_name( "Debian Security Advisory DSA 3493-1 (xerces-c - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:49 +0530 (Tue, 08 Mar 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3493.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "xerces-c on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 3.1.1-3+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 3.1.1-5.1+deb8u1.

We recommend that you upgrade your xerces-c packages." );
	script_tag( name: "summary", value: "Gustavo Grieco discovered that xerces-c, a validating XML parser library
for C++, mishandles certain kinds of malformed input documents,
resulting in buffer overflows during processing and error reporting.
These flaws could lead to a denial of service in applications using the
xerces-c library, or potentially, to the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxerces-c-dev", ver: "3.1.1-3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c-doc", ver: "3.1.1-3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c-samples", ver: "3.1.1-3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c3.1", ver: "3.1.1-3+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c-dev", ver: "3.1.1-5.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c-doc", ver: "3.1.1-5.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c-samples", ver: "3.1.1-5.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c3.1", ver: "3.1.1-5.1+deb8u1", rls: "DEB8" ) ) != NULL){
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

