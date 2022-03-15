if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703677" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-5418", "CVE-2016-6250", "CVE-2016-7166" );
	script_name( "Debian Security Advisory DSA 3677-1 (libarchive - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-09-25 00:00:00 +0200 (Sun, 25 Sep 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3677.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libarchive on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 3.1.2-11+deb8u3.

We recommend that you upgrade your libarchive packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in libarchive, a multi-format archive and compression library, which may lead to
denial of service (memory consumption and application crash), bypass of sandboxing
restrictions and overwrite arbitrary files with arbitrary data from an
archive, or the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bsdcpio", ver: "3.1.2-11+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsdtar", ver: "3.1.2-11+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive-dev:amd64", ver: "3.1.2-11+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive-dev:i386", ver: "3.1.2-11+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive13:amd64", ver: "3.1.2-11+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive13:i386", ver: "3.1.2-11+deb8u3", rls: "DEB8" ) ) != NULL){
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

