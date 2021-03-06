if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703682" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-5180" );
	script_name( "Debian Security Advisory DSA 3682-1 (c-ares - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-10-05 15:43:05 +0530 (Wed, 05 Oct 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3682.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "c-ares on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1.10.0-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 1.12.0-1.

We recommend that you upgrade your c-ares packages." );
	script_tag( name: "summary", value: "Gzob Qq discovered that the
query-building functions in c-ares, an asynchronous DNS request library would
not correctly process crafted query names, resulting in a heap buffer overflow
and potentially leading to arbitrary code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libc-ares-dev", ver: "1.10.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc-ares2:amd64", ver: "1.10.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libc-ares2:i386", ver: "1.10.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

